"""Defense component feature flags.

Import DEFENSE_CONFIG and read these at decision time to toggle components on/off.
Set via environment variables or override dict for ablation runs.

  SENTINEL_DISABLE_NORMALIZER=1         disable recursive multi-encoding normalizer
  SENTINEL_DISABLE_TAINT=1              disable taint-based untrusted text extraction
  SENTINEL_DISABLE_AUTHORIZATION=1      disable intent check + arg authorization
  SENTINEL_DISABLE_CORPUS=1             disable cross-record corpus matching
  SENTINEL_DISABLE_MEMORY_RULES=1       disable memory write protection
  SENTINEL_DISABLE_OUTBOUND_FLOW=1      disable outbound data flow rule
"""

from __future__ import annotations

import os


class DefenseConfig:
    """Runtime toggles for ablation experiments.  All components are ON by default."""

    def __init__(self) -> None:
        self._overrides: dict[str, bool] = {}

    def _flag(self, env_var: str, key: str) -> bool:
        if key in self._overrides:
            return self._overrides[key]
        return os.environ.get(env_var, "").strip() not in ("1", "true", "yes")

    @property
    def normalizer_enabled(self) -> bool:
        return self._flag("SENTINEL_DISABLE_NORMALIZER", "normalizer")

    @property
    def taint_enabled(self) -> bool:
        return self._flag("SENTINEL_DISABLE_TAINT", "taint")

    @property
    def authorization_enabled(self) -> bool:
        return self._flag("SENTINEL_DISABLE_AUTHORIZATION", "authorization")

    @property
    def corpus_enabled(self) -> bool:
        return self._flag("SENTINEL_DISABLE_CORPUS", "corpus")

    @property
    def memory_rules_enabled(self) -> bool:
        return self._flag("SENTINEL_DISABLE_MEMORY_RULES", "memory_rules")

    @property
    def outbound_flow_enabled(self) -> bool:
        return self._flag("SENTINEL_DISABLE_OUTBOUND_FLOW", "outbound_flow")

    def override(self, **kwargs: bool) -> "DefenseConfig":
        """Return a new config with specific keys overridden (for testing/ablation)."""
        cfg = DefenseConfig()
        cfg._overrides = {**self._overrides, **kwargs}
        return cfg


DEFENSE_CONFIG = DefenseConfig()
