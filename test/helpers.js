const fs = require('fs');
const path = require('path');
const assert = require('assert');

const SAMPLES_DIR = path.join(__dirname, 'samples');
const PROJECT_ROOT = path.join(__dirname, '..');

function loadEmlRaw(filename) {
  const filePath = path.join(SAMPLES_DIR, filename);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Test sample not found: ${filename}. Run 'npm run test:gen-samples' first.`);
  }
  return fs.readFileSync(filePath, 'latin1');
}

function loadEml(filename) {
  const rawContent = loadEmlRaw(filename);
  const { parseHeaders, extractEmailHeaders } = require(path.join(PROJECT_ROOT, 'lib/headerParser'));
  const { parseMimeStructure } = require(path.join(PROJECT_ROOT, 'lib/mimeParser'));
  const { extractBodies, htmlToPlainText } = require(path.join(PROJECT_ROOT, 'lib/bodyExtractor'));
  const { listAttachments } = require(path.join(PROJECT_ROOT, 'lib/attachmentExtractor'));
  const { checkSecurity } = require(path.join(PROJECT_ROOT, 'lib/securityChecker'));

  const headerData = parseHeaders(rawContent);
  const headers = extractEmailHeaders(headerData);
  const mimeTree = parseMimeStructure(rawContent);
  const bodies = extractBodies(mimeTree);

  if (bodies.html) {
    bodies.htmlAsText = htmlToPlainText(bodies.html);
  }

  const attachments = listAttachments(mimeTree);

  const emlData = {
    file: path.join(SAMPLES_DIR, filename),
    rawContent,
    headers,
    mimeTree,
    bodies,
    attachments
  };

  emlData.security = checkSecurity(emlData);

  return emlData;
}

function makeTempDir() {
  const tmpDir = path.join(__dirname, '.tmp', Date.now().toString(36) + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpDir, { recursive: true });
  return tmpDir;
}

function cleanupTempDir(dir) {
  if (fs.existsSync(dir)) {
    for (const entry of fs.readdirSync(dir)) {
      const entryPath = path.join(dir, entry);
      const stat = fs.statSync(entryPath);
      if (stat.isDirectory()) {
        cleanupTempDir(entryPath);
      } else {
        fs.unlinkSync(entryPath);
      }
    }
    fs.rmdirSync(dir);
  }
}

function computeSHA256(buf) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function assertContains(str, substr, msg) {
  assert.ok(str.includes(substr), msg || `Expected string to contain "${substr}"`);
}

function assertNotContains(str, substr, msg) {
  assert.ok(!str.includes(substr), msg || `Expected string NOT to contain "${substr}"`);
}

module.exports = {
  SAMPLES_DIR,
  PROJECT_ROOT,
  loadEmlRaw,
  loadEml,
  makeTempDir,
  cleanupTempDir,
  computeSHA256,
  assertContains,
  assertNotContains
};
