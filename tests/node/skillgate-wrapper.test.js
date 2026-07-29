"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const wrapper = require("../../npm/bin/skillgate.js");

test("hashes release assets with SHA-256", () => {
  assert.equal(
    wrapper.sha256(Buffer.from("SkillGate")),
    "4ec10057ca7325a3cdb0665e5dd3b5653195c56b86d45ebc03162abec6df7915",
  );
});

test("builds a pinned release URL", () => {
  const previous = process.env.SKILLGATE_VERSION;
  process.env.SKILLGATE_VERSION = "v0.1.3";
  try {
    assert.equal(
      wrapper.releaseBaseUrl(),
      "https://github.com/charliechenye/SkillGate/releases/download/v0.1.3",
    );
  } finally {
    if (previous === undefined) delete process.env.SKILLGATE_VERSION;
    else process.env.SKILLGATE_VERSION = previous;
  }
});

test("allows a deterministic platform override for tests", () => {
  const previous = process.env.SKILLGATE_PLATFORM_KEY;
  process.env.SKILLGATE_PLATFORM_KEY = "test-x64";
  try {
    assert.equal(wrapper.platformKey(), "test-x64");
  } finally {
    if (previous === undefined) delete process.env.SKILLGATE_PLATFORM_KEY;
    else process.env.SKILLGATE_PLATFORM_KEY = previous;
  }
});

test("prefers an explicit asset URL", () => {
  assert.equal(
    wrapper.assetUrl({ url: "https://mirror.example.invalid/skillgate" }),
    "https://mirror.example.invalid/skillgate",
  );
});
