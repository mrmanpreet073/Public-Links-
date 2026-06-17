import { readFileSync } from "node:fs";
import path from "node:path";   

// export const PRIVATE_KEY = readFileSync(path.resolve("cert/private-key.pem"));
// export const PUBLIC_KEY = readFileSync(path.resolve("cert/public-key.pub"));

export const PRIVATE_KEY = process.env.PRIVATE_KEY
  ?? readFileSync(path.resolve("cert/private-key.pem"));

export const PUBLIC_KEY = process.env.PUBLIC_KEY
  ?? readFileSync(path.resolve("cert/public-key.pub"));