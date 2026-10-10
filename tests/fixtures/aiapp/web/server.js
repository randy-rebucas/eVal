const express = require('express');
const path = require('path');
const fs = require('node:fs');
import helper from './helper';
import { magic } from 'express-magic-router';

function auth(req) {
  throw new Error("Not implemented");
}
module.exports = { express, path, fs, helper, magic, auth };
