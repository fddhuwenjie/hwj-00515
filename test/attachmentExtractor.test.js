const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { describe, it, before, after } = require('./harness');
const { PROJECT_ROOT, loadEml, makeTempDir, cleanupTempDir, computeSHA256 } = require('./helpers');

const { extractAttachments, listAttachments, findAllAttachments, computeSHA256: libComputeSHA256, sanitizeFilename, resolveFilenameConflict, getFileExtension } = require(path.join(PROJECT_ROOT, 'lib/attachmentExtractor'));
const { extractInlineImages } = require(path.join(PROJECT_ROOT, 'lib/bodyExtractor'));

let tmpDir = null;

describe('attachmentExtractor - Attachment Listing & Metadata', function() {
  it('finds no attachments in plain text email', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    assert.strictEqual(eml.attachments.length, 0);
  });

  it('lists multiple attachments in multipart/mixed (sample3)', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    assert.ok(eml.attachments.length >= 3, `Expected at least 3 attachments, got ${eml.attachments.length}`);
    const filenames = eml.attachments.map(a => a.filename);
    assert.ok(filenames.some(f => f.includes('项目报告') || f.endsWith('.pdf')), 'Should have PDF');
    assert.ok(filenames.includes('screenshot.png'), 'Should have screenshot.png');
    assert.ok(filenames.some(f => f.includes('需求文档') || f.endsWith('.docx')), 'Should have DOCX');
  });

  it('lists attachments with correct content types', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    const types = eml.attachments.map(a => a.contentType.toLowerCase());
    assert.ok(types.some(t => t.includes('application/pdf')), 'Should have PDF content type');
    assert.ok(types.some(t => t.includes('image/png')), 'Should have PNG content type');
  });

  it('provides correct file sizes for attachments', function() {
    const eml = loadEml('07_multipart_mixed.eml');
    for (const att of eml.attachments) {
      assert.ok(att.size > 0, 'Attachment should have non-zero size');
      assert.ok(typeof att.sizeFormatted === 'string', 'Should have formatted size');
    }
  });

  it('provides SHA256 hash for each attachment', function() {
    const eml = loadEml('07_multipart_mixed.eml');
    for (const att of eml.attachments) {
      assert.ok(att.sha256, 'Should have SHA256');
      assert.strictEqual(att.sha256.length, 64, 'SHA256 should be 64 hex chars');
      assert.ok(/^[0-9a-f]{64}$/i.test(att.sha256), 'SHA256 should be valid hex');
    }
  });

  it('preserves Content-ID for inline attachments', function() {
    const eml = loadEml('09_multipart_related.eml');
    const allAtts = findAllAttachments(eml.mimeTree);
    const inlineImg = allAtts.find(a => a.contentId === 'logo_cid');
    assert.ok(inlineImg, 'Should find inline image with CID');
  });

  it('inline images with Content-ID are recognized via extractInlineImages', function() {
    const eml = loadEml('09_multipart_related.eml');
    const images = extractInlineImages(eml.mimeTree);
    assert.ok(images.length >= 1, 'Should extract inline images');
    assert.strictEqual(images[0].cid, 'logo_cid');
    assert.strictEqual(images[0].contentType.toLowerCase(), 'image/png');
    assert.ok(images[0].size > 0, 'Inline image should have size');
  });

  it('findAllAttachments handles various criteria', function() {
    const eml = loadEml('07_multipart_mixed.eml');
    const atts = findAllAttachments(eml.mimeTree);
    assert.ok(atts.length >= 2);
    for (const att of atts) {
      assert.ok(att.filename || att.contentDisposition === 'attachment',
        'Should match attachment detection criteria');
    }
  });
});

describe('attachmentExtractor - SHA256 Computation', function() {
  it('libComputeSHA256 matches Node crypto result', function() {
    const data = Buffer.from('test data for sha256');
    const expected = computeSHA256(data);
    const actual = libComputeSHA256(data);
    assert.strictEqual(actual, expected);
  });

  it('SHA256 is consistent for same content', function() {
    const data = Buffer.from('consistent content');
    const h1 = libComputeSHA256(data);
    const h2 = libComputeSHA256(data);
    assert.strictEqual(h1, h2);
  });

  it('SHA256 differs for different content', function() {
    const h1 = libComputeSHA256(Buffer.from('content A'));
    const h2 = libComputeSHA256(Buffer.from('content B'));
    assert.notStrictEqual(h1, h2);
  });
});

describe('attachmentExtractor - Filename Sanitization & Conflict Resolution', function() {
  it('sanitizeFilename replaces path separators and illegal chars', function() {
    assert.strictEqual(sanitizeFilename('a/b\\c:d*e?f"g<h>i|j.txt'), 'a_b_c_d_e_f_g_h_i_j.txt');
  });

  it('sanitizeFilename removes control characters', function() {
    assert.strictEqual(sanitizeFilename('test\x00\x01file.txt'), 'testfile.txt');
  });

  it('sanitizeFilename strips leading dots', function() {
    assert.strictEqual(sanitizeFilename('...hidden.txt'), 'hidden.txt');
  });

  it('sanitizeFilename strips trailing dots', function() {
    assert.strictEqual(sanitizeFilename('file.txt...'), 'file.txt');
  });

  it('sanitizeFilename returns "unnamed" for empty result', function() {
    assert.strictEqual(sanitizeFilename(''), 'unnamed');
    assert.strictEqual(sanitizeFilename('...'), 'unnamed');
  });

  it('sanitizeFilename truncates long filenames preserving extension', function() {
    const longName = 'a'.repeat(250) + '.txt';
    const sanitized = sanitizeFilename(longName);
    assert.ok(sanitized.length <= 200);
    assert.ok(sanitized.endsWith('.txt'));
  });

  it('resolveFilenameConflict handles first occurrence', function() {
    const used = new Set();
    assert.strictEqual(resolveFilenameConflict('file.txt', used), 'file.txt');
  });

  it('resolveFilenameConflict appends _1 for first conflict', function() {
    const used = new Set(['file.txt'.toLowerCase()]);
    assert.strictEqual(resolveFilenameConflict('file.txt', used), 'file_1.txt');
  });

  it('resolveFilenameConflict increments counter for multiple conflicts', function() {
    const used = new Set(['file.txt'.toLowerCase(), 'file_1.txt'.toLowerCase(), 'file_2.txt'.toLowerCase()]);
    assert.strictEqual(resolveFilenameConflict('file.txt', used), 'file_3.txt');
  });

  it('resolveFilenameConflict is case-insensitive', function() {
    const used = new Set(['file.txt'.toLowerCase()]);
    assert.strictEqual(resolveFilenameConflict('FILE.TXT', used), 'FILE_1.TXT');
  });

  it('getFileExtension extracts lowercase extension with dot', function() {
    assert.strictEqual(getFileExtension('report.pdf'), '.pdf');
    assert.strictEqual(getFileExtension('IMAGE.PNG'), '.png');
    assert.strictEqual(getFileExtension('noext'), '.');
  });
});

describe('attachmentExtractor - File Extraction to Disk', function() {
  before(function() {
    tmpDir = makeTempDir();
  });

  after(function() {
    if (tmpDir) cleanupTempDir(tmpDir);
  });

  it('extractAttachments writes files to output directory', function() {
    const eml = loadEml('07_multipart_mixed.eml');
    const outDir = path.join(tmpDir, 'extract1');
    const results = extractAttachments(eml.mimeTree, outDir);

    assert.ok(results.length >= 2, 'Should extract at least 2 files');
    for (const r of results) {
      assert.ok(fs.existsSync(r.path), `File ${r.filename} should exist on disk`);
      const stats = fs.statSync(r.path);
      assert.strictEqual(stats.size, r.size, 'File size should match reported size');
    }
  });

  it('extracted files SHA256 matches computed hash', function() {
    const eml = loadEml('07_multipart_mixed.eml');
    const outDir = path.join(tmpDir, 'extract2');
    const results = extractAttachments(eml.mimeTree, outDir);

    for (const r of results) {
      const buf = fs.readFileSync(r.path);
      const actualHash = computeSHA256(buf);
      assert.strictEqual(actualHash, r.sha256, `SHA256 mismatch for ${r.filename}`);
    }
  });

  it('handles duplicate filenames by renaming (case-insensitive)', function() {
    const eml = loadEml('10_duplicate_filenames.eml');
    const outDir = path.join(tmpDir, 'dup');
    const results = extractAttachments(eml.mimeTree, outDir);

    assert.strictEqual(results.length, 3, 'Should extract 3 attachments');
    const filenames = results.map(r => r.filename.toLowerCase());
    const unique = new Set(filenames);
    assert.strictEqual(unique.size, 3, 'All extracted filenames should be unique');

    assert.ok(filenames.includes('readme.txt'));
    assert.ok(filenames.includes('readme_1.txt'));
    assert.ok(filenames.includes('readme_2.txt'));

    for (const r of results) {
      assert.ok(fs.existsSync(r.path), `File should exist: ${r.path}`);
    }
  });

  it('creates output directory if it does not exist', function() {
    const eml = loadEml('07_multipart_mixed.eml');
    const outDir = path.join(tmpDir, 'nested', 'deep', 'dir');
    extractAttachments(eml.mimeTree, outDir);
    assert.ok(fs.existsSync(outDir), 'Output directory should be created');
  });

  it('extractAttachments returns complete metadata', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    const outDir = path.join(tmpDir, 'meta');
    const results = extractAttachments(eml.mimeTree, outDir);

    for (const r of results) {
      assert.ok(r.filename, 'Should have filename');
      assert.ok(r.originalFilename, 'Should have originalFilename');
      assert.ok(r.path, 'Should have path');
      assert.strictEqual(typeof r.size, 'number');
      assert.ok(r.sizeFormatted, 'Should have sizeFormatted');
      assert.ok(r.contentType, 'Should have contentType');
      assert.ok(r.sha256, 'Should have sha256');
      assert.ok(r.extension, 'Should have extension');
      assert.strictEqual(typeof r.isInline, 'boolean');
      assert.strictEqual(typeof r.isAttachment, 'boolean');
    }
  });

  it('sample3 attachments have non-zero SHA256', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    for (const att of eml.attachments) {
      assert.ok(att.sha256 && att.sha256.length === 64, `Attachment ${att.filename} should have valid SHA256`);
    }
  });

  it('sample2 inline image is detected with cid', function() {
    const eml = loadEml('orig_sample2_html_inline.eml');
    const allAtts = findAllAttachments(eml.mimeTree);
    const inlineWithCid = allAtts.find(a => a.contentId === 'logo_image');
    assert.ok(inlineWithCid, 'Should find inline image with cid logo_image');
    assert.ok(inlineWithCid.body, 'Should have body content');
  });
});
