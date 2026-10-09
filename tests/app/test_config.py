from __future__ import annotations

import pytest

from eval_app.config import database_url


@pytest.mark.parametrize("raw,expected", [
    ("postgres://u:p@h:5432/db", "postgresql+psycopg://u:p@h:5432/db"),
    ("postgresql://u:p@dpg-x.oregon-postgres.render.com/db?sslmode=require",
     "postgresql+psycopg://u:p@dpg-x.oregon-postgres.render.com/db?sslmode=require"),
    ("postgresql+psycopg://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
    ("sqlite:///:memory:", "sqlite:///:memory:"),
    ("", ""),
])
def test_database_url_selects_psycopg3(raw, expected):
    assert database_url(raw) == expected
