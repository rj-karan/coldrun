#!/usr/bin/env node
const os = require("os");
const fs = require("node:fs");
console.log("hello from node", typeof os.platform, typeof fs.readFileSync);
