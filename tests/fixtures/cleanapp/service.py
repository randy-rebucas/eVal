"""A small, well-behaved module used to check analyzers for false positives."""

import logging
import os

import requests

log = logging.getLogger(__name__)
API_URL = os.environ.get("RATES_API_URL", "https://api.example.com/rates")


def fetch_rates(session: requests.Session) -> dict:
    response = session.get(API_URL, timeout=(3, 10))
    response.raise_for_status()
    return response.json()


def total(values: list[float]) -> float:
    return sum(values)
