"""Local-development convenience: load ``.env`` if python-dotenv is installed.

Variables already present in the process environment always win (``override=False``), so container and
production configuration is never replaced by a stray file.
"""

from __future__ import annotations


def load_local_env() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(override=False)
