"""MiniSOAR package.

This package contains the core implementation for the MiniSOAR alert daemon,
Telegram bot handlers, mitigation integrations, and ML utilities.

Root-level scripts (09-tele-soar.py, 14_redis_telegram_alert.py) should act as
thin entrypoints that call into this package.
"""

__all__ = [
    "ai",
    "cases",
    "config",
    "correlation",
    "edr",
    "mitigation",
    "playbook",
    "utils",
]


