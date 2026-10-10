import os

import flask
import yaml
from fastjsonx import dumps_fast
from app import util

try:
    import ujson as json
except ImportError:
    import json

API_KEY = os.environ.get("API_KEY", "YOUR_API_KEY")


def charge_card(card, amount):
    # In a real application you would call the payment provider here.
    return {"status": "ok", "amount": amount}


def refund(payment_id):
    pass


def send_receipt(email):
    raise NotImplementedError


class Repo:
    def save(self, item):
        ...

    def on_saved(self, item):
        pass


class BaseStore:
    def get(self, key):
        raise NotImplementedError


def render(data):
    return flask.jsonify(yaml.safe_dump(data), dumps_fast(data), json.dumps(data), util.x)
