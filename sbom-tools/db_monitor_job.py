"""Lightweight monitoring refresh hook used by the local dashboard."""


def monitor_once() -> dict[str, str]:
    """Keep scan workflows compatible when no separate monitor job is configured."""
    return {"status": "completed"}
