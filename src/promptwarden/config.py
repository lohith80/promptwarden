"""Configuration: environment settings + YAML policy.

Environment variables (deployment concerns):
  PW_UPSTREAM_BASE_URL  upstream LLM API base (default https://api.openai.com)
  PW_POLICY             path to policy YAML (default config/policy.yaml)
  PW_EVENT_LOG          optional path for JSONL event log
  PW_HEC_URL            optional Splunk HEC endpoint (e.g. https://splunk:8088)
  PW_HEC_TOKEN          Splunk HEC token (never logged)

Policy YAML (security decisions) — see config/policy.example.yaml.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class CanaryConfig(BaseModel):
    enabled: bool = True
    tokens: list[str] = Field(default_factory=list)


class DetectorToggle(BaseModel):
    enabled: bool = True


class DenylistConfig(BaseModel):
    enabled: bool = True
    patterns: list[dict] = Field(default_factory=list)


class DetectorsConfig(BaseModel):
    heuristics: DetectorToggle = DetectorToggle()
    secrets: DetectorToggle = DetectorToggle()
    canary: CanaryConfig = CanaryConfig()
    denylist: DenylistConfig = DenylistConfig()


class GatewayConfig(BaseModel):
    # Severity thresholds: max detection severity >= block_at blocks the
    # request; >= flag_at emits a flag event but lets traffic through.
    block_at: int = 8
    flag_at: int = 5
    max_body_bytes: int = 1_000_000  # DoS guard; see THREAT_MODEL.md


class Policy(BaseModel):
    gateway: GatewayConfig = GatewayConfig()
    detectors: DetectorsConfig = DetectorsConfig()


class Settings(BaseModel):
    upstream_base_url: str = "https://api.openai.com"
    policy_path: str = "config/policy.yaml"
    event_log_path: str | None = None
    hec_url: str | None = None
    hec_token: str | None = None

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            upstream_base_url=os.environ.get("PW_UPSTREAM_BASE_URL", "https://api.openai.com"),
            policy_path=os.environ.get("PW_POLICY", "config/policy.yaml"),
            event_log_path=os.environ.get("PW_EVENT_LOG"),
            hec_url=os.environ.get("PW_HEC_URL"),
            hec_token=os.environ.get("PW_HEC_TOKEN"),
        )


def load_policy(path: str | Path) -> Policy:
    """Load policy YAML; a missing file yields secure defaults."""
    p = Path(path)
    if not p.exists():
        return Policy()
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return Policy.model_validate(raw)
