"""
NTP-SCTAP Configuration Module.

Provides centralized application settings, environment-aware configuration,
and default values for all platform components.
"""

from config.settings import Config, get_config

__all__ = ["Config", "get_config"]
