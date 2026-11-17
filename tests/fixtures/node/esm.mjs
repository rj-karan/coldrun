import path from "node:path";
import { readFile } from "fs/promises";
console.log("esm ok", path.sep, typeof readFile);
