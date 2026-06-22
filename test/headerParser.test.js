const assert = require('assert');
const { describe, it } = require('./harness');
const path = require('path');
const { PROJECT_ROOT, loadEml, loadEmlRaw, assertContains } = require('./helpers');

const { parseHeaders, extractEmailHeaders, decodeHeaderValue, parseAddressList, iconvDecode } = require(path.join(PROJECT_ROOT, 'lib/headerParser'));

describe('headerParser - Header End Detection', function() {
  it('detects header end with CRLF CRLF (Windows style)', function() {
    const raw = loadEmlRaw('01_header_crlf.eml');
    const hd = parseHeaders(raw);
    assert.ok(hd.bodyStart > 0, 'Should find header end position');
    assert.strictEqual(hd.getFirst('from'), 'sender@example.com');
    assert.strictEqual(hd.getFirst('to'), 'recipient@example.com');
  });

  it('detects header end with LF LF (Unix style)', function() {
    const raw = loadEmlRaw('02_header_lf.eml');
    const hd = parseHeaders(raw);
    assert.ok(hd.bodyStart > 0, 'Should find header end position');
    assert.strictEqual(hd.getFirst('from'), 'sender@example.com');
    assert.strictEqual(hd.getFirst('subject'), 'LF Test');
  });

  it('returns content length when no header separator found', function() {
    const raw = 'From: a@b.com\nTo: c@d.com\nNo separator here';
    const hd = parseHeaders(raw);
    assert.strictEqual(hd.bodyStart, raw.length);
  });
});

describe('headerParser - RFC 2047 Encoded-Word Decoding', function() {
  it('decodes UTF-8 Base64 encoded subject (sample1_plain)', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    assert.strictEqual(eml.headers.subject, '你好，这是一封纯文本测试邮件');
  });

  it('decodes UTF-8 Base64 encoded From/To names', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    assert.strictEqual(eml.headers.from.name, '张三');
    assert.strictEqual(eml.headers.from.email, 'zhangsan@example.com');
    assert.strictEqual(eml.headers.to[0].name, '李四');
    assert.strictEqual(eml.headers.to[0].email, 'lisi@example.com');
  });

  it('handles multiple consecutive encoded-words with whitespace between', function() {
    const raw = loadEmlRaw('03_folded_headers.eml');
    const hd = parseHeaders(raw);
    const subject = hd.getFirst('subject');
    assert.ok(subject.length > 0, 'Subject should be decoded');
    assert.ok(!subject.includes('=?'), 'Should not contain encoded-word markers');
  });

  it('decodes mixed encodings (UTF-8 B, UTF-8 Q, ISO-8859-1 Q)', function() {
    const eml = loadEml('15_rfc2047_mixed.eml');
    assert.ok(eml.headers.subject.length > 0, 'Subject should be decoded');
    assert.ok(!eml.headers.subject.includes('=?'), 'Subject should not contain encoded markers');
  });

  it('decodeHeaderValue handles plain text passthrough', function() {
    assert.strictEqual(decodeHeaderValue('plain text'), 'plain text');
    assert.strictEqual(decodeHeaderValue(''), '');
    assert.strictEqual(decodeHeaderValue(null), null);
  });

  it('decodeHeaderValue decodes single Base64 encoded word', function() {
    const encoded = '=?UTF-8?B?5L2g5aW9?=';
    const decoded = decodeHeaderValue(encoded);
    assert.strictEqual(decoded, '你好');
  });

  it('decodeHeaderValue decodes single Q encoded word', function() {
    const encoded = '=?UTF-8?Q?hello_world?=';
    const decoded = decodeHeaderValue(encoded);
    assert.strictEqual(decoded, 'hello world');
  });
});

describe('headerParser - Folded Header Unfolding', function() {
  it('unfolds multi-line To header with comma continuation', function() {
    const eml = loadEml('03_folded_headers.eml');
    assert.ok(eml.headers.to.length >= 3, 'Should have at least 3 recipients');
    const emails = eml.headers.to.map(a => a.email);
    assert.ok(emails.includes('recipient1@example.com'));
    assert.ok(emails.includes('recipient2@example.com'));
    assert.ok(emails.includes('recipient3@example.com'));
  });

  it('unfolds folded Subject with multiple encoded-words', function() {
    const eml = loadEml('03_folded_headers.eml');
    assert.strictEqual(eml.headers.messageId, '<folded-header-test@example.com>');
    assert.ok(eml.headers.subject.length > 0);
    assert.ok(!eml.headers.subject.includes('=?'), 'Subject should be fully decoded');
  });
});

describe('headerParser - Address Parsing (From/To/Cc/Bcc/Reply-To)', function() {
  it('parses simple single address', function() {
    const addrs = parseAddressList('user@example.com');
    assert.strictEqual(addrs.length, 1);
    assert.strictEqual(addrs[0].email, 'user@example.com');
    assert.strictEqual(addrs[0].name, '');
  });

  it('parses address with quoted name', function() {
    const addrs = parseAddressList('"John Doe" <john@example.com>');
    assert.strictEqual(addrs.length, 1);
    assert.strictEqual(addrs[0].name, 'John Doe');
    assert.strictEqual(addrs[0].email, 'john@example.com');
  });

  it('parses address with unquoted name', function() {
    const addrs = parseAddressList('Jane Smith <jane@example.com>');
    assert.strictEqual(addrs.length, 1);
    assert.strictEqual(addrs[0].name, 'Jane Smith');
    assert.strictEqual(addrs[0].email, 'jane@example.com');
  });

  it('parses comma-separated address list', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    assert.strictEqual(eml.headers.to.length, 2);
    assert.strictEqual(eml.headers.to[0].email, 'lisi@example.com');
    assert.strictEqual(eml.headers.to[1].email, 'wangwu@example.com');
  });

  it('parses addresses with embedded commas in quoted names', function() {
    const eml = loadEml('12_address_edge.eml');
    const toEmails = eml.headers.to.map(a => a.email);
    assert.ok(toEmails.includes('alice@example.com'), 'Should include alice');
    assert.ok(toEmails.includes('charlie@example.com'), 'Should include charlie');
    assert.ok(toEmails.includes('dave@example.com'), 'Should include dave');
    assert.ok(toEmails.length >= 3, `Should have at least 3 To addresses, got ${toEmails.length}`);
  });

  it('parses Cc list properly', function() {
    const eml = loadEml('12_address_edge.eml');
    assert.ok(eml.headers.cc.length >= 2, 'Should have at least 2 Cc');
    const ccEmails = eml.headers.cc.map(a => a.email);
    assert.ok(ccEmails.includes('eve@example.com'));
    assert.ok(ccEmails.includes('frank@example.com'));
  });

  it('parses Bcc list', function() {
    const eml = loadEml('12_address_edge.eml');
    assert.strictEqual(eml.headers.bcc.length, 1);
    assert.strictEqual(eml.headers.bcc[0].email, 'grace@example.com');
  });

  it('parses Reply-To header', function() {
    const eml = loadEml('12_address_edge.eml');
    assert.strictEqual(eml.headers.replyTo.length, 1);
    assert.strictEqual(eml.headers.replyTo[0].email, 'support@example.com');
  });

  it('handles From with quoted name containing escaped quotes', function() {
    const eml = loadEml('12_address_edge.eml');
    assert.strictEqual(eml.headers.from.email, 'john@example.com');
    assert.ok(eml.headers.from.name.includes('John'), 'Should parse name with special chars');
  });

  it('handles empty/null input gracefully', function() {
    assert.deepStrictEqual(parseAddressList(null), []);
    assert.deepStrictEqual(parseAddressList(''), []);
    assert.deepStrictEqual(parseAddressList(undefined), []);
  });

  it('handles address with angle brackets only (no name)', function() {
    const addrs = parseAddressList('<nobracket@example.com>');
    assert.ok(addrs.length >= 1, 'Should parse at least 1 address');
    assert.ok(addrs[0].email.includes('nobracket@example.com'), 'Should contain the email');
  });
});

describe('headerParser - Subject, Date, Message-ID', function() {
  it('parses Subject correctly from plain sample', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    assert.strictEqual(eml.headers.subject, '你好，这是一封纯文本测试邮件');
  });

  it('handles empty Subject', function() {
    const eml = loadEml('14_empty_subject.eml');
    assert.strictEqual(eml.headers.subject, '');
  });

  it('parses Date as valid Date object', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    assert.ok(eml.headers.date instanceof Date);
    assert.ok(!isNaN(eml.headers.date.getTime()), 'Date should be valid');
    assert.strictEqual(eml.headers.date.getFullYear(), 2025);
    assert.strictEqual(eml.headers.date.getMonth(), 0);
  });

  it('preserves original dateString', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    assert.strictEqual(eml.headers.dateString, 'Mon, 20 Jan 2025 10:30:00 +0800');
  });

  it('parses Message-ID correctly', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    assert.strictEqual(eml.headers.messageId, '<plain-email-001@example.com>');
  });

  it('handles missing Message-ID gracefully', function() {
    const eml = loadEml('18_missing_messageid.eml');
    assert.strictEqual(eml.headers.messageId, '');
  });

  it('parses minimal headers without Date/Message-ID', function() {
    const eml = loadEml('13_minimal_headers.eml');
    assert.strictEqual(eml.headers.from.email, 'minimal@example.com');
    assert.strictEqual(eml.headers.subject, 'Minimal');
    assert.strictEqual(eml.headers.date, null);
    assert.strictEqual(eml.headers.messageId, '');
  });
});

describe('headerParser - Character Set Decoding (iconvDecode)', function() {
  it('decodes UTF-8', function() {
    const buf = Buffer.from('你好', 'utf8');
    assert.strictEqual(iconvDecode(buf, 'utf-8'), '你好');
  });

  it('decodes US-ASCII / ISO-8859-1', function() {
    const buf = Buffer.from('hello', 'latin1');
    assert.strictEqual(iconvDecode(buf, 'us-ascii'), 'hello');
    assert.strictEqual(iconvDecode(buf, 'iso-8859-1'), 'hello');
  });

  it('decodes GBK encoded email subject and body', function() {
    const eml = loadEml('04_gbk_encoded.eml');
    assert.ok(eml.headers.subject.length > 0, 'GBK subject should be decoded');
    assert.ok(!eml.headers.subject.includes('=?'), 'Subject should not have encoded markers');
  });

  it('falls back to UTF-8 for unknown charset', function() {
    const buf = Buffer.from('test', 'utf8');
    assert.strictEqual(iconvDecode(buf, 'UNKNOWN-CHARSET'), 'test');
  });
});
