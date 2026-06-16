#!/usr/bin/env node
"use strict";

const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { URL } = require("node:url");

const REPOSITORY = "charliechenye/SkillGate";
const DEFAULT_RELEASE_BASE = `https://github.com/${REPOSITORY}/releases`;
const MANIFEST_NAME = "skillgate-release.json";
const MAX_REDIRECTS = 5;
const MANIFEST_BYTE_LIMIT = 1024 * 1024;
const INSECURE_HTTP_TEST_FLAG = "SKILLGATE_ALLOW_INSECURE_HTTP_FOR_TESTS";

function platformKey() {
  if (process.env.SKILLGATE_PLATFORM_KEY) {
    return process.env.SKILLGATE_PLATFORM_KEY;
  }
  return `${process.platform}-${process.arch}`;
}

function cacheRoot() {
  if (process.env.SKILLGATE_CACHE_DIR) {
    return process.env.SKILLGATE_CACHE_DIR;
  }
  if (process.platform === "win32" && process.env.LOCALAPPDATA) {
    return path.join(process.env.LOCALAPPDATA, "SkillGate", "node-wrapper");
  }
  return path.join(os.homedir(), ".cache", "skillgate", "node-wrapper");
}

function releaseBaseUrl() {
  if (process.env.SKILLGATE_RELEASE_BASE_URL) {
    return process.env.SKILLGATE_RELEASE_BASE_URL.replace(/\/$/, "");
  }
  if (process.env.SKILLGATE_VERSION) {
    return `${DEFAULT_RELEASE_BASE}/download/${process.env.SKILLGATE_VERSION}`;
  }
  return `${DEFAULT_RELEASE_BASE}/latest/download`;
}

function manifestUrl() {
  return process.env.SKILLGATE_MANIFEST_URL || `${releaseBaseUrl()}/${MANIFEST_NAME}`;
}

function readJsonFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function validateByteLimit(byteLimit, label) {
  if (!Number.isSafeInteger(byteLimit) || byteLimit < 0) {
    throw new Error(`${label} byte limit must be a non-negative integer`);
  }
}

function validateProtocol(parsed) {
  if (parsed.protocol === "https:" || parsed.protocol === "file:") {
    return;
  }
  if (parsed.protocol === "http:" && process.env[INSECURE_HTTP_TEST_FLAG] === "1") {
    return;
  }
  if (parsed.protocol === "http:") {
    throw new Error(`insecure HTTP download requires ${INSECURE_HTTP_TEST_FLAG}=1`);
  }
  throw new Error(`unsupported download protocol: ${parsed.protocol}`);
}

function rejectIfContentLengthExceeds(response, byteLimit, url) {
  const contentLength = response.headers["content-length"];
  if (contentLength === undefined) {
    return;
  }
  if (!/^\d+$/.test(contentLength)) {
    throw new Error(`invalid Content-Length while fetching ${url}`);
  }
  const expectedBytes = Number(contentLength);
  if (!Number.isSafeInteger(expectedBytes)) {
    throw new Error(`Content-Length is too large while fetching ${url}`);
  }
  if (expectedBytes > byteLimit) {
    throw new Error(
      `download for ${url} exceeds limit of ${byteLimit} bytes from Content-Length`,
    );
  }
}

function download(url, byteLimit, redirects = 0) {
  try {
    validateByteLimit(byteLimit, "download");
  } catch (error) {
    return Promise.reject(error);
  }
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(url);
      validateProtocol(parsed);
    } catch (error) {
      reject(error);
      return;
    }
    if (parsed.protocol === "file:") {
      fs.stat(parsed, (statError, stats) => {
        if (statError) {
          reject(statError);
          return;
        }
        if (stats.size > byteLimit) {
          reject(new Error(`download for ${url} exceeds limit of ${byteLimit} bytes`));
          return;
        }
        fs.readFile(parsed, (error, data) => {
          if (error) {
            reject(error);
          } else {
            resolve(data);
          }
        });
      });
      return;
    }
    const client = parsed.protocol === "http:" ? http : https;
    const request = client.get(parsed, (response) => {
      if (
        response.statusCode >= 300 &&
        response.statusCode < 400 &&
        response.headers.location
      ) {
        response.resume();
        if (redirects >= MAX_REDIRECTS) {
          reject(new Error(`too many redirects while fetching ${url}`));
          return;
        }
        resolve(
          download(new URL(response.headers.location, parsed).toString(), byteLimit, redirects + 1),
        );
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`HTTP ${response.statusCode} while fetching ${url}`));
        return;
      }
      try {
        rejectIfContentLengthExceeds(response, byteLimit, url);
      } catch (error) {
        response.resume();
        reject(error);
        return;
      }
      const chunks = [];
      let totalBytes = 0;
      let exceeded = false;
      response.on("data", (chunk) => {
        if (exceeded) {
          return;
        }
        totalBytes += chunk.length;
        if (totalBytes > byteLimit) {
          exceeded = true;
          response.destroy(new Error(`download for ${url} exceeds limit of ${byteLimit} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => resolve(Buffer.concat(chunks)));
      response.on("error", reject);
    });
    request.on("error", reject);
  });
}

function assetByteLimit(asset) {
  const sizeBytes = asset && asset.size_bytes;
  if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 0) {
    throw new Error("release asset size_bytes must be a non-negative integer");
  }
  return sizeBytes;
}

async function loadManifest() {
  if (process.env.SKILLGATE_MANIFEST_PATH) {
    return readJsonFile(process.env.SKILLGATE_MANIFEST_PATH);
  }
  return JSON.parse((await download(manifestUrl(), MANIFEST_BYTE_LIMIT)).toString("utf8"));
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function assetUrl(asset) {
  if (asset.url) {
    return asset.url;
  }
  return `${releaseBaseUrl()}/${asset.name}`;
}

function currentRecordPath() {
  return path.join(cacheRoot(), "current.json");
}

function binaryPath(version, asset) {
  return path.join(cacheRoot(), version, asset.name);
}

function verifyCached(record) {
  if (!record || !record.path || !record.sha256) {
    throw new Error("cached SkillGate record is malformed");
  }
  const data = fs.readFileSync(record.path);
  const actual = sha256(data);
  if (actual !== record.sha256) {
    throw new Error(`cached SkillGate checksum mismatch: expected ${record.sha256}, got ${actual}`);
  }
  return record.path;
}

async function ensureBinary() {
  if (process.env.SKILLGATE_NO_UPDATE_CHECK === "1") {
    return verifyCached(readJsonFile(currentRecordPath()));
  }
  const manifest = await loadManifest();
  if (manifest.schema_version !== 1) {
    throw new Error("unsupported SkillGate release manifest schema");
  }
  const key = platformKey();
  const asset = manifest.assets && manifest.assets[key];
  if (!asset) {
    throw new Error(`unsupported platform for SkillGate release asset: ${key}`);
  }
  const version = manifest.version || "unknown";
  const destination = binaryPath(version, asset);
  if (fs.existsSync(destination)) {
    return verifyCached({ path: destination, sha256: asset.sha256 });
  }
  const data = await download(assetUrl(asset), assetByteLimit(asset));
  const actual = sha256(data);
  if (actual !== asset.sha256) {
    throw new Error(`SkillGate checksum mismatch: expected ${asset.sha256}, got ${actual}`);
  }
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, data, { mode: 0o755 });
  if (process.platform !== "win32") {
    fs.chmodSync(destination, 0o755);
  }
  fs.mkdirSync(cacheRoot(), { recursive: true });
  fs.writeFileSync(
    currentRecordPath(),
    JSON.stringify({ version, platform: key, path: destination, sha256: asset.sha256 }, null, 2),
  );
  return destination;
}

function run(binary, args) {
  const useShell = process.platform === "win32" && /\.(cmd|bat)$/i.test(binary);
  const child = childProcess.spawn(binary, args, {
    stdio: "inherit",
    windowsHide: true,
    shell: useShell,
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code === null ? 1 : code);
  });
  child.on("error", (error) => {
    console.error(`skillgate: failed to execute downloaded binary: ${error.message}`);
    process.exit(1);
  });
}

async function main() {
  try {
    const args = process.argv.slice(2);
    if (args[0] === "--") {
      args.shift();
    }
    run(await ensureBinary(), args);
  } catch (error) {
    console.error(`skillgate: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  assetUrl,
  binaryPath,
  cacheRoot,
  download,
  ensureBinary,
  loadManifest,
  platformKey,
  releaseBaseUrl,
  sha256,
};
