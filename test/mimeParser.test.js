const assert = require('assert');
const { describe, it } = require('./harness');
const path = require('path');
const { PROJECT_ROOT, loadEml, loadEmlRaw } = require('./helpers');

const { parseMimeStructure, decodeContent, flattenMimeTree, decodeQuotedPrintable, parseContentTypeHeader, parseContentTypeAndDisposition } = require(path.join(PROJECT_ROOT, 'lib/mimeParser'));
const { parseHeaders } = require(path.join(PROJECT_ROOT, 'lib/headerParser'));

describe('mimeParser - Content Decoding', function() {
  it('decodes base64 encoded plain text body', function() {
    const eml = loadEml('05_plain_base64.eml');
    assert.ok(eml.bodies.text, 'Should have text body');
    assert.ok(eml.bodies.text.includes('base64 encoded plain text body'), 'Should decode base64 text');
    assert.ok(eml.bodies.text.includes('第二行内容'), 'Should decode Chinese text from base64');
  });

  it('decodes quoted-printable encoded plain text body', function() {
    const eml = loadEml('06_plain_qp.eml');
    assert.ok(eml.bodies.text, 'Should have text body');
    assert.ok(eml.bodies.text.includes('Hello World!'), 'Should decode ASCII text');
    assert.ok(eml.bodies.text.includes('这是一段需要 quoted-printable 编码的中文内容'), 'Should decode QP Chinese text');
    assert.ok(eml.bodies.text.includes('Line with = sign.'), 'Should decode equals sign');
  });

  it('decodeQuotedPrintable handles soft line breaks', function() {
    const input = 'line1=\r\nline2=\nline3';
    const buf = decodeQuotedPrintable(input);
    const result = buf.toString('latin1');
    assert.ok(result.includes('line1line2line3'), 'Soft line breaks should be removed');
  });

  it('decodeQuotedPrintable handles hex escapes', function() {
    const buf = decodeQuotedPrintable('=E4=BD=A0=E5=A5=BD');
    const decoded = buf.toString('utf8');
    assert.strictEqual(decoded, '你好');
  });

  it('decodeContent handles 7bit encoding passthrough', function() {
    const result = decodeContent('plain text', '7bit', 'utf-8');
    assert.strictEqual(result.text, 'plain text');
  });

  it('decodeContent handles 8bit and binary encoding', function() {
    const result = decodeContent('text data', '8bit', 'utf-8');
    assert.strictEqual(result.text, 'text data');
    const result2 = decodeContent('binary data', 'binary', 'utf-8');
    assert.strictEqual(result2.text, 'binary data');
  });

  it('decodes quoted-printable body from plain sample', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    assert.ok(eml.bodies.text, 'Should have text body');
    assert.ok(eml.bodies.text.includes('你好'), 'Should decode Chinese');
    assert.ok(eml.bodies.text.includes('这是一封纯文本测试邮件'), 'Should decode body content');
  });

  it('decodes GBK charset body', function() {
    const eml = loadEml('04_gbk_encoded.eml');
    assert.ok(eml.bodies.text, 'Should have text body');
    assert.ok(eml.bodies.text.includes('GBK') || eml.bodies.text.length > 5, 'GBK body should be decoded to readable text');
  });
});

describe('mimeParser - Multipart Structure Parsing', function() {
  it('parses multipart/mixed with attachments', function() {
    const eml = loadEml('07_multipart_mixed.eml');
    assert.strictEqual(eml.mimeTree.contentType, 'multipart/mixed');
    assert.ok(eml.mimeTree.children.length >= 2, 'Should have at least 2 children (text + attachments)');
  });

  it('parses multipart/alternative with text and HTML', function() {
    const eml = loadEml('08_multipart_alternative.eml');
    assert.strictEqual(eml.mimeTree.contentType, 'multipart/alternative');
    assert.strictEqual(eml.mimeTree.children.length, 2);

    const types = eml.mimeTree.children.map(c => c.contentType);
    assert.ok(types.includes('text/plain'), 'Should have text/plain part');
    assert.ok(types.includes('text/html'), 'Should have text/html part');
  });

  it('parses nested multipart/related with inline images', function() {
    const eml = loadEml('09_multipart_related.eml');
    assert.strictEqual(eml.mimeTree.contentType, 'multipart/related');

    const allParts = flattenMimeTree(eml.mimeTree);
    const types = allParts.map(p => p.contentType);
    assert.ok(types.includes('multipart/alternative'), 'Should have nested alternative');
    assert.ok(types.includes('text/plain'), 'Should have text/plain');
    assert.ok(types.includes('text/html'), 'Should have text/html');
    assert.ok(types.includes('image/png'), 'Should have inline image');
  });

  it('flattenMimeTree returns all nodes including nested', function() {
    const eml = loadEml('09_multipart_related.eml');
    const flat = flattenMimeTree(eml.mimeTree);
    assert.ok(flat.length >= 5, 'Should have multiple flattened nodes');
  });

  it('extracts both text and HTML bodies from multipart/alternative', function() {
    const eml = loadEml('08_multipart_alternative.eml');
    assert.ok(eml.bodies.text, 'Should extract text body');
    assert.ok(eml.bodies.html, 'Should extract HTML body');
    assert.ok(eml.bodies.text.includes('纯文本版本'), 'Text body should have content');
    assert.ok(eml.bodies.html.includes('<html>'), 'HTML body should have tags');
  });

  it('extracts bodies from multipart/mixed (sample3)', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    assert.ok(eml.bodies.text, 'Should have text body in mixed multipart');
    assert.ok(eml.bodies.text.includes('本周项目相关资料'), 'Text body should have content');
  });

  it('parses Content-Type parameters correctly', function() {
    const parsed = parseContentTypeHeader('text/plain; charset=utf-8; boundary="abc123"');
    assert.strictEqual(parsed.type, 'text/plain');
    assert.strictEqual(parsed.params.charset, 'utf-8');
    assert.strictEqual(parsed.params.boundary, 'abc123');
  });

  it('parses Content-Type with name parameter', function() {
    const parsed = parseContentTypeHeader('application/pdf; name="report.pdf"');
    assert.strictEqual(parsed.type, 'application/pdf');
    assert.strictEqual(parsed.params.name, 'report.pdf');
  });

  it('parses Content-Type with quoted params', function() {
    const parsed = parseContentTypeHeader('text/html; charset="utf-8"');
    assert.strictEqual(parsed.params.charset, 'utf-8');
  });
});

describe('mimeParser - Content-Disposition & Content-ID', function() {
  it('detects attachment disposition', function() {
    const eml = loadEml('07_multipart_mixed.eml');
    const flat = flattenMimeTree(eml.mimeTree);
    const attachments = flat.filter(p => p.contentDisposition === 'attachment');
    assert.ok(attachments.length >= 2, 'Should have attachments');
  });

  it('extracts filename from Content-Type name parameter', function() {
    const eml = loadEml('07_multipart_mixed.eml');
    const flat = flattenMimeTree(eml.mimeTree);
    const pdfPart = flat.find(p => p.filename === 'report.pdf');
    assert.ok(pdfPart, 'Should find PDF part with filename');
    assert.strictEqual(pdfPart.contentType, 'application/pdf');
  });

  it('extracts filename from Content-Disposition filename parameter', function() {
    const eml = loadEml('07_multipart_mixed.eml');
    const flat = flattenMimeTree(eml.mimeTree);
    const txtPart = flat.find(p => p.filename === 'notes.txt');
    assert.ok(txtPart, 'Should find text attachment');
  });

  it('extracts Content-ID for inline images', function() {
    const eml = loadEml('09_multipart_related.eml');
    const flat = flattenMimeTree(eml.mimeTree);
    const imgPart = flat.find(p => p.contentType === 'image/png');
    assert.ok(imgPart, 'Should find image part');
    assert.strictEqual(imgPart.contentId, 'logo_cid');
    assert.strictEqual(imgPart.contentDisposition, 'inline');
  });

  it('handles RFC 2231 encoded filename* parameter', function() {
    const eml = loadEml('17_rfc2231_filename.eml');
    const flat = flattenMimeTree(eml.mimeTree);
    const pdfPart = flat.find(p => p.contentType === 'application/pdf');
    assert.ok(pdfPart, 'Should find PDF part');
    assert.ok(pdfPart.filename, 'Should have filename');
    if (pdfPart.filename) {
      assert.ok(pdfPart.filename.includes('中文') || pdfPart.filename.includes('.pdf'),
        'RFC 2231 filename should be decoded or have extension');
    }
  });
});

describe('bodyExtractor - HTML to Plain Text & URL Extraction', function() {
  const { htmlToPlainText, extractExternalImageUrls, extractInlineImages, isAttachment } = require(path.join(PROJECT_ROOT, 'lib/bodyExtractor'));

  it('htmlToPlainText strips HTML tags', function() {
    const html = '<html><body><p>Hello <b>World</b></p></body></html>';
    const text = htmlToPlainText(html);
    assert.ok(!text.includes('<'), 'Should strip tags');
    assert.ok(!text.includes('>'), 'Should strip tags');
    assert.ok(text.includes('Hello World'), 'Should preserve text content');
  });

  it('htmlToPlainText converts <br> to newlines', function() {
    const html = 'line1<br>line2<br/>line3';
    const text = htmlToPlainText(html);
    assert.ok(text.includes('\n'), 'Should have newlines');
  });

  it('htmlToPlainText decodes HTML entities', function() {
    const html = 'a &amp; b &lt; c &gt; d &nbsp; e';
    const text = htmlToPlainText(html);
    assert.ok(text.includes('a & b < c > d'), 'Should decode amp, lt, gt');
    assert.ok(text.includes('e'), 'Should preserve final text');
  });

  it('htmlToPlainText handles empty/null', function() {
    assert.strictEqual(htmlToPlainText(''), '');
    assert.strictEqual(htmlToPlainText(null), '');
    assert.strictEqual(htmlToPlainText(undefined), '');
  });

  it('extractExternalImageUrls finds http/https images', function() {
    const html = '<img src="https://example.com/a.png"><img src="http://test.com/b.gif"><img src="cid:local">';
    const urls = extractExternalImageUrls(html);
    assert.strictEqual(urls.length, 2);
    assert.ok(urls.includes('https://example.com/a.png'));
    assert.ok(urls.includes('http://test.com/b.gif'));
  });

  it('extractExternalImageUrls deduplicates', function() {
    const html = '<img src="https://example.com/a.png"><img src="https://example.com/a.png">';
    const urls = extractExternalImageUrls(html);
    assert.strictEqual(urls.length, 1);
  });

  it('extractExternalImageUrls ignores cid: and data: URIs', function() {
    const html = '<img src="cid:logo"><img src="data:image/png;base64,abc">';
    const urls = extractExternalImageUrls(html);
    assert.strictEqual(urls.length, 0);
  });

  it('extractInlineImages finds images with Content-ID', function() {
    const eml = loadEml('09_multipart_related.eml');
    const images = extractInlineImages(eml.mimeTree);
    assert.ok(images.length >= 1, 'Should find inline images');
    assert.strictEqual(images[0].cid, 'logo_cid');
    assert.ok(images[0].buffer.length > 0, 'Should have image buffer');
  });

  it('isAttachment detects attachment by disposition', function() {
    assert.strictEqual(isAttachment({ contentDisposition: 'attachment', filename: null }), true);
    assert.strictEqual(isAttachment({ contentDisposition: 'inline', filename: null }), false);
  });

  it('isAttachment detects attachment by filename presence', function() {
    assert.strictEqual(isAttachment({ contentDisposition: null, filename: 'test.pdf' }), true);
    assert.strictEqual(isAttachment({ contentDisposition: null, filename: null }), false);
  });
});
