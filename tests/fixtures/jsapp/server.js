const express = require("express");
const cors = require("cors");
const fs = require("fs");
const { Item } = require("./models");

const app = express();
app.use(cors());
app.use(express.json());

app.post("/items", async (req, res) => {
  const item = await Item.create(req.body);
  res.json(item);
});

app.get("/calc", (req, res) => {
  const template = fs.readFileSync("./template.txt", "utf8");
  res.send(template + eval(req.query.expr));
});

app.listen(3000);
