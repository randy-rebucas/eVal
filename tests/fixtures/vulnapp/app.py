import sqlite3

import requests
from flask import Flask, request

from models import Order, User, db

app = Flask(__name__)
app.secret_key = "s3cr3t-dev-key-1234"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


@app.route("/users/<name>")
def find_user(name):
    conn = sqlite3.connect("app.db")
    rows = conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()
    return {"rows": rows}


@app.route("/orders", methods=["POST"])
def create_order():
    order = Order(**request.json)
    db.session.add(order)
    db.session.commit()
    return {"id": order.id}


@app.route("/report")
def report():
    users = User.query.all()
    out = []
    for u in users:
        orders = Order.query.filter_by(user_id=u.id).all()
        out.append({"user": u.name, "orders": len(orders)})
    rate = requests.get("https://api.example.com/rates").json()
    return {"report": out, "rate": rate}


if __name__ == "__main__":
    app.run(debug=True)
