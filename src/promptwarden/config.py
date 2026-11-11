"""Configuration: environment settings + YAML policy.

Environment variables (deployment concerns):
  PW_UPSTREAM_BASE_URL      upstream LLM API base (default https://api.openai.com)
  PW_UPSTREAM_API_KEY       provider key held by the gateway; injected only for
                            authenticated apps (never for anonymous traffic)
  PW_POLICY                 path to policy YAML (default config/policy.yaml)
  PW_POLICY_RELOAD_SECONDS  poll the policy file and hot-reload on change (0 = off)
  PW_EVENT_LOG              optional path for JSONL event log
  PW_STDOUT_EVENTS          emit events to stdout (default true)
  PW_EVENT_QUEUE_SIZE       bounded event queue size (default 10000)
  PW_HEC_URL / PW_HEC_TOKEN Splunk HTTP Event Collector sink (token never logged)
  PW_WEBHOOK_URL / PW_WEBHOOK_TOKEN  generic HTTPS JSON sink (bearer auth)
  PW_SYSLOG_ADDR            CEF over syslog, e.g. udp://siem.example.com:514
  PW_TRUSTED_PROXY_HOPS     number of trusted reverse proxies in front of the
                            gateway; selects the client IP from X-Forwarded-For
  PW_METRICS_ENABLED        expose /metrics (default true)

Policy YAML (security decisions) - see config/policy.example.yaml. The policy
schema is strict: unknown keys are rejected, because a typo that silently falls
back to a default is a security bug in a control like this.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

logger = logging.getLogger("promptwarden.config")

Mode = Literal["enforce", "monitor"]
DirectionName = Literal["inbound", "outbound"]

_KEY_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PolicyError(ValueError):
    """Raised when a policy file is invalid. The message is operator-facing."""


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CanaryConfig(StrictModel):
    enabled: bool = True
    tokens: list[str] = Field(default_factory=list)


class DetectorToggle(StrictModel):
    enabled: bool = True


class SecretsConfig(StrictModel):
    enabled: bool = True
    # block:  a secret in a prompt blocks the request (v0.1 behavior).
    # redact: the matched span is replaced with [REDACTED:<rule>] and the
    #         request continues. Use when blocking pushes users to bypass
    #         the gateway. Applies to inbound traffic only.
    inbound_action: Literal["block", "redact"] = "block"


class ExfilConfig(StrictModel):
    enabled: bool = True
    # When non-empty, any image URL in model output must be on one of these
    # domains (exact host or subdomain). Deterministic control against
    # zero-click image-beacon exfiltration.
    allowed_image_domains: list[str] = Field(default_factory=list)


class DenyRuleConfig(StrictModel):
    id: str
    pattern: str
    severity: int = Field(6, ge=1, le=10)
    description: str = "Denylist pattern match"
    directions: list[DirectionName] = Field(default_factory=lambda: ["inbound", "outbound"])

    @field_validator("pattern")
    @classmethod
    def _pattern_compiles(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from exc
        return value


class DenylistConfig(StrictModel):
    enabled: bool = True
    patterns: list[DenyRuleConfig] = Field(default_factory=list)


class DetectorsConfig(StrictModel):
    heuristics: DetectorToggle = DetectorToggle()
    secrets: SecretsConfig = SecretsConfig()
    canary: CanaryConfig = CanaryConfig()
    denylist: DenylistConfig = DenylistConfig()
    exfil: ExfilConfig = ExfilConfig()


class GatewayConfig(StrictModel):
    # enforce: block at/above block_at. monitor: never block, record what
    # would have been blocked (shadow mode for safe rollout).
    mode: Mode = "enforce"
    # Severity thresholds: max detection severity >= block_at blocks the
    # request; >= flag_at emits a flag event but lets traffic through.
    block_at: int = Field(8, ge=1, le=10)
    flag_at: int = Field(5, ge=1, le=10)
    max_body_bytes: int = Field(1_000_000, gt=0)  # DoS guard; see THREAT_MODEL.md
    # What to do when the inspection engine itself raises: fail_closed blocks
    # the request, fail_open lets it through. Either way an event is emitted.
    on_error: Literal["fail_closed", "fail_open"] = "fail_closed"
    upstream_timeout_seconds: float = Field(120.0, gt=0)
    # Return rule IDs and descriptions in block responses. Turn off when the
    # gateway response can reach an untrusted end user (it is a bypass oracle).
    expose_detections: bool = True

    @model_validator(mode="after")
    def _thresholds_ordered(self) -> GatewayConfig:
        if self.flag_at > self.block_at:
            raise ValueError("flag_at must be <= block_at")
        return self


class AuthConfig(StrictModel):
    # When true, every request must present a gateway key that maps to an app.
    required: bool = False


class StreamingConfig(StrictModel):
    # window: release tokens as they arrive, holding back the last
    #         holdback_chars until they have been inspected.
    # buffer: hold the whole stream, inspect it, then replay it.
    mode: Literal["window", "buffer"] = "window"
    holdback_chars: int = Field(256, ge=32, le=65536)


class InspectionConfig(StrictModel):
    # Messages with these roles are operator-authored. They are still scanned
    # for secrets and denylist terms, but not for injection phrasing (a system
    # prompt that says "never reveal your system prompt" is not an attack).
    # Set to [] if clients of the gateway are themselves untrusted.
    trusted_roles: list[str] = Field(default_factory=lambda: ["system", "developer"])


class LimitsConfig(StrictModel):
    requests_per_minute: int = Field(0, ge=0)  # 0 = unlimited
    burst: int = Field(0, ge=0)  # 0 = same as requests_per_minute
    max_output_tokens: int = Field(0, ge=0)  # 0 = no cap
    allowed_models: list[str] = Field(default_factory=list)  # glob; empty = any


class ToolsConfig(StrictModel):
    # Tool names (glob) the model may never call / the only ones it may call.
    denied: list[str] = Field(default_factory=list)
    allowed: list[str] = Field(default_factory=list)
    # name -> sha256 of the canonical tool definition (promptwarden tool-hash).
    pinned: dict[str, str] = Field(default_factory=dict)
    # Reject tool definitions that are not pinned at all.
    require_pinned: bool = False
    # Trust-on-first-use: alert when a tool definition changes while the
    # gateway is running (rug pull), even without pins.
    drift_detection: bool = True
    # Scan tool names/descriptions/schemas for hidden instructions.
    inspect_definitions: bool = True

    @field_validator("pinned")
    @classmethod
    def _pins_are_sha256(cls, value: dict[str, str]) -> dict[str, str]:
        for name, digest in value.items():
            if not _SHA256_RE.match(digest):
                raise ValueError(f"pin for tool {name!r} must be 64 lowercase hex chars (sha256)")
        return value


class AuditConfig(StrictModel):
    # Emit one API Activity event per request (metadata only, never content).
    enabled: bool = False


class AppConfig(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    # sha256 hashes of gateway keys (promptwarden keygen). Plaintext keys are
    # never stored in policy.
    key_hashes: list[str] = Field(default_factory=list)
    # Name of an environment variable holding the provider API key for this
    # app. The gateway swaps it in, so app teams never hold provider keys.
    upstream_key_env: str | None = None
    mode: Mode | None = None
    block_at: int | None = Field(None, ge=1, le=10)
    flag_at: int | None = Field(None, ge=1, le=10)
    limits: LimitsConfig | None = None
    tools: ToolsConfig | None = None

    @field_validator("key_hashes")
    @classmethod
    def _hash_format(cls, value: list[str]) -> list[str]:
        for item in value:
            if not _KEY_HASH_RE.match(item):
                raise ValueError(
                    "key_hashes entries must look like sha256:<64 hex>; "
                    "generate with `promptwarden keygen`"
                )
        return value


@dataclass(frozen=True)
class EffectiveConfig:
    """Per-request settings after app overrides are applied."""

    app_id: str
    mode: Mode
    block_at: int
    flag_at: int
    limits: LimitsConfig
    tools: ToolsConfig


class Policy(StrictModel):
    version: int = 1
    gateway: GatewayConfig = GatewayConfig()
    auth: AuthConfig = AuthConfig()
    streaming: StreamingConfig = StreamingConfig()
    inspection: InspectionConfig = InspectionConfig()
    detectors: DetectorsConfig = DetectorsConfig()
    tools: ToolsConfig = ToolsConfig()
    limits: LimitsConfig = LimitsConfig()
    audit: AuditConfig = AuditConfig()
    apps: list[AppConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _cross_checks(self) -> Policy:
        seen_ids: set[str] = set()
        seen_hashes: set[str] = set()
        for app in self.apps:
            if app.id in seen_ids:
                raise ValueError(f"duplicate app id: {app.id}")
            seen_ids.add(app.id)
            for key_hash in app.key_hashes:
                if key_hash in seen_hashes:
                    raise ValueError(f"key hash reused across apps (app {app.id})")
                seen_hashes.add(key_hash)
            block_at = app.block_at if app.block_at is not None else self.gateway.block_at
            flag_at = app.flag_at if app.flag_at is not None else self.gateway.flag_at
            if flag_at > block_at:
                raise ValueError(f"app {app.id}: flag_at must be <= block_at")
        if self.auth.required and not seen_hashes:
            raise ValueError("auth.required is true but no app defines key_hashes")
        return self

    def effective(self, app: AppConfig | None = None) -> EffectiveConfig:
        gw = self.gateway
        if app is None:
            return EffectiveConfig(
                app_id="default",
                mode=gw.mode,
                block_at=gw.block_at,
                flag_at=gw.flag_at,
                limits=self.limits,
                tools=self.tools,
            )
        return EffectiveConfig(
            app_id=app.id,
            mode=app.mode or gw.mode,
            block_at=app.block_at if app.block_at is not None else gw.block_at,
            flag_at=app.flag_at if app.flag_at is not None else gw.flag_at,
            limits=app.limits or self.limits,
            tools=app.tools or self.tools,
        )

    def fingerprint(self) -> str:
        """Short stable hash of the policy, carried in every event so the SOC
        can tell which policy version produced a verdict."""
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise PolicyError(f"{name} must be an integer, got {raw!r}") from exc


class Settings(BaseModel):
    upstream_base_url: str = "https://api.openai.com"
    upstream_api_key: str | None = None
    policy_path: str = "config/policy.yaml"
    policy_reload_seconds: int = 0
    event_log_path: str | None = None
    stdout_events: bool = True
    event_queue_size: int = 10_000
    # Deliver events on a background thread so sink latency never touches the
    # request path. Tests and library callers can turn this off.
    event_async: bool = True
    hec_url: str | None = None
    hec_token: str | None = None
    webhook_url: str | None = None
    webhook_token: str | None = None
    syslog_addr: str | None = None
    trusted_proxy_hops: int = 0
    metrics_enabled: bool = True

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            upstream_base_url=os.environ.get("PW_UPSTREAM_BASE_URL", "https://api.openai.com"),
            upstream_api_key=os.environ.get("PW_UPSTREAM_API_KEY") or None,
            policy_path=os.environ.get("PW_POLICY", "config/policy.yaml"),
            policy_reload_seconds=_env_int("PW_POLICY_RELOAD_SECONDS", 0),
            event_log_path=os.environ.get("PW_EVENT_LOG") or None,
            stdout_events=_env_bool("PW_STDOUT_EVENTS", True),
            event_queue_size=_env_int("PW_EVENT_QUEUE_SIZE", 10_000),
            hec_url=os.environ.get("PW_HEC_URL") or None,
            hec_token=os.environ.get("PW_HEC_TOKEN") or None,
            webhook_url=os.environ.get("PW_WEBHOOK_URL") or None,
            webhook_token=os.environ.get("PW_WEBHOOK_TOKEN") or None,
            syslog_addr=os.environ.get("PW_SYSLOG_ADDR") or None,
            trusted_proxy_hops=_env_int("PW_TRUSTED_PROXY_HOPS", 0),
            metrics_enabled=_env_bool("PW_METRICS_ENABLED", True),
        )


def _format_validation_error(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors():
        location = ".".join(str(part) for part in err["loc"]) or "<root>"
        lines.append(f"  {location}: {err['msg']}")
    return "invalid policy:\n" + "\n".join(lines)


def parse_policy(raw: object) -> Policy:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyError("invalid policy: top level must be a mapping")
    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(_format_validation_error(exc)) from exc


def load_policy(path: str | Path, *, must_exist: bool = False) -> Policy:
    """Load policy YAML. A missing file yields secure defaults (and a warning)
    unless must_exist is set. An invalid file always raises PolicyError: the
    gateway refuses to start on a policy it cannot fully understand."""
    p = Path(path)
    if not p.exists():
        if must_exist:
            raise PolicyError(f"policy file not found: {p}")
        logger.warning("policy file %s not found; using built-in secure defaults", p)
        return Policy()
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid policy: YAML parse error: {exc}") from exc
    return parse_policy(raw)
