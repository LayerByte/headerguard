const crypto = require("crypto");
const dns = require("dns").promises;
const fs = require("fs");
const https = require("https");
const http = require("http");
const { URL } = require("url");

const PROJECT_NAME = "Headerguard";
const PROJECT_FOCUS = "Website HTTP security-header checker.";

function usage() {
  console.log(`${PROJECT_NAME} - ${PROJECT_FOCUS}`);
  console.log("Usage: node src/index.js --mode file|json|url|headers|dns|password --value <input>");
}

function getArg(name, fallback = "") {
  const index = process.argv.indexOf(name);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

function hashFile(path) {
  const hash = crypto.createHash("sha256");
  const data = fs.readFileSync(path);
  hash.update(data);
  console.log(`Path: ${path}`);
  console.log(`Size: ${data.length} bytes`);
  console.log(`SHA-256: ${hash.digest("hex")}`);
}

function validateJson(path) {
  const data = JSON.parse(fs.readFileSync(path, "utf8"));
  console.log("Valid JSON");
  console.log(`Top-level type: ${Array.isArray(data) ? "array" : typeof data}`);
}

function analyzeUrl(value) {
  const parsed = new URL(value);
  console.log(`Protocol: ${parsed.protocol}`);
  console.log(`Host: ${parsed.hostname}`);
  console.log(`Path length: ${parsed.pathname.length}`);
  console.log(`Uses HTTPS: ${parsed.protocol === "https:"}`);
}

function requestHeaders(value) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(value);
    const client = parsed.protocol === "http:" ? http : https;
    const request = client.request(parsed, { method: "HEAD", timeout: 8000 }, (response) => {
      for (const key of ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "access-control-allow-origin"]) {
        console.log(`${key}: ${response.headers[key] || "missing"}`);
      }
      resolve();
    });
    request.on("timeout", () => request.destroy(new Error("request timed out")));
    request.on("error", reject);
    request.end();
  });
}

async function dnsLookup(host) {
  const records = await dns.lookup(host, { all: true });
  for (const record of records) {
    console.log(`${record.family}: ${record.address}`);
  }
}

function passwordScore(value) {
  let score = 0;
  if (value.length >= 12) score += 2;
  if (/[a-z]/.test(value)) score += 1;
  if (/[A-Z]/.test(value)) score += 1;
  if (/[0-9]/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;
  console.log(`Offline score: ${score}/6`);
  console.log("This tool never transmits the provided value.");
}

async function main() {
  const mode = getArg("--mode", "url");
  const value = getArg("--value", "");
  if (!value) {
    usage();
    return;
  }
  if (mode === "file") hashFile(value);
  else if (mode === "json") validateJson(value);
  else if (mode === "url") analyzeUrl(value);
  else if (mode === "headers") await requestHeaders(value);
  else if (mode === "dns") await dnsLookup(value);
  else if (mode === "password") passwordScore(value);
  else throw new Error("Unknown mode");
}

main().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
