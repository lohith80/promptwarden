"""Gateway authentication and upstream credential custody.

Two problems are solved here:

1. Identity. Each application gets its own gateway key, so every event names
   the app that produced it and policy can differ per app.
2. Key custody. The provider API key can live at the gateway (one env var per
   app). Application teams then never hold a provider key: they hold a gateway
   key that only works through inspection and can be revoked by removing one
   hash from policy.

Gateway keys are 32 random bytes, so a plain SHA-256 is an appropriate way to
store them (there is nothing to brute-force). Only hashes appear in policy.

A client presents its gateway key in one of two ways:

  X-PromptWarden-Key: pw_...            provider key (if any) stays in Authorization
  Authorization: Bearer pw_...          drop-in for OpenAI SDKs (api_key=pw_...);
                                        requires the gateway to hold the provider key
"""

from __future__ import annotations

import hashlib
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass

from .config import AppConfig, EffectiveConfig, Policy, PolicyError

KEY_PREFIX = "pw_"
KEY_HEADER = "x-promptwarden-key"


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuthResult:
    effective: EffectiveConfig
    # Authorization header value to send upstream, or None to send none.
    upstream_authorization: str | None = None
    # Set when the request must be rejected.
    error_status: int = 0
    error_type: str = ""
    error_message: str = ""

    @property
    def ok(self) -> bool:
        return self.error_status == 0


class AppIndex:
    """Lookup from key hash to app, plus resolved upstream credentials."""

    def __init__(self, policy: Policy, environ: Mapping[str, str] | None = None,
                 global_upstream_key: str | None = None):
        env = os.environ if environ is None else environ
        self._policy = policy
        self._by_hash: dict[str, AppConfig] = {}
        self._upstream_keys: dict[str, str] = {}
        self._global_upstream_key = global_upstream_key
        for app in policy.apps:
            for key_hash in app.key_hashes:
                self._by_hash[key_hash] = app
            if app.upstream_key_env:
                value = env.get(app.upstream_key_env)
                if not value:
                    raise PolicyError(
                        f"app {app.id}: environment variable {app.upstream_key_env} "
                        "(upstream_key_env) is not set"
                    )
                self._upstream_keys[app.id] = value

    def resolve(self, headers: Mapping[str, str]) -> AuthResult:
        default = self._policy.effective()
        client_authorization = headers.get("authorization")
        presented = headers.get(KEY_HEADER)
        via_authorization = False
        if not presented and client_authorization:
            scheme, _, token = client_authorization.partition(" ")
            if scheme.lower() == "bearer" and token.strip().startswith(KEY_PREFIX):
                presented = token.strip()
                via_authorization = True

        if not presented:
            if self._policy.auth.required:
                return AuthResult(default, None, 401, "promptwarden_unauthorized",
                                  "a gateway key is required")
            # Anonymous traffic never gets a gateway-held provider key.
            return AuthResult(default, client_authorization)

        app = self._by_hash.get(hash_key(presented))
        if app is None:
            return AuthResult(default, None, 401, "promptwarden_unauthorized",
                              "invalid gateway key")

        effective = self._policy.effective(app)
        held = self._upstream_keys.get(app.id) or self._global_upstream_key
        if held:
            return AuthResult(effective, f"Bearer {held}")
        if via_authorization:
            # The Authorization header carried the gateway key, so there is no
            # provider credential to forward. Never send a gateway key upstream.
            return AuthResult(effective, None, 502, "promptwarden_config",
                              "no upstream credential is configured for this app")
        return AuthResult(effective, client_authorization)
