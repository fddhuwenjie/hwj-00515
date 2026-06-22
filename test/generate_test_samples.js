const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OUT_DIR = path.join(__dirname, 'samples');
if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

function encH(s) {
  return '=?UTF-8?B?' + Buffer.from(s, 'utf8').toString('base64') + '?=';
}

function encHQ(s) {
  return '=?UTF-8?Q?' + encodeQPForHeader(s) + '?=';
}

function encodeQPForHeader(s) {
  let r = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 127) {
      const b = Buffer.from(s[i], 'utf8');
      for (let j = 0; j < b.length; j++) r += '=' + b[j].toString(16).toUpperCase().padStart(2, '0');
    } else if (c === 32) {
      r += '_';
    } else if (c === 61 || c === 63 || c === 95) {
      r += '=' + c.toString(16).toUpperCase().padStart(2, '0');
    } else {
      r += s[i];
    }
  }
  return r;
}

function encodeQP(s) {
  let r = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 127) {
      const b = Buffer.from(s[i], 'utf8');
      for (let j = 0; j < b.length; j++) r += '=' + b[j].toString(16).toUpperCase().padStart(2, '0');
    } else if (c === 61) r += '=3D';
    else r += s[i];
  }
  return r;
}

function b64wrap(b) {
  return b.toString('base64').match(/.{1,72}/g).join('\n');
}

function writeEml(name, content) {
  fs.writeFileSync(path.join(OUT_DIR, name), content, 'latin1');
  console.log('✓ ' + name);
}

function buildHeaderEndCRLF() {
  return 'From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: CRLF Test\r\n\r\nBody content';
}

function buildHeaderEndLF() {
  return 'From: sender@example.com\nTo: recipient@example.com\nSubject: LF Test\n\nBody content';
}

function buildFoldedHeader() {
  return [
    'From: "Sender Name" <sender@example.com>',
    'To: "First Recipient" <recipient1@example.com>,',
    ' "Second Recipient" <recipient2@example.com>,',
    '\t"Third Recipient" <recipient3@example.com>',
    'Subject: =?UTF-8?B?5L2g5aW9?=',
    ' =?UTF-8?B?5LiL5aSn6ICF?=',
    ' =?UTF-8?B?5paH56ug?=',
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <folded-header-test@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Folded header body.'
  ].join('\r\n');
}

function buildGBKEncoded() {
  const gbkSubject = '=?GBK?B?suLK1A==?=';
  const gbkBytes = Buffer.from([
    0xB2, 0xE2, 0xCA, 0xD7, 0x47, 0x42, 0x4B, 0xB1, 0xE0, 0xC2, 0xEB,
    0xB5, 0xC4, 0xD5, 0xFD, 0xCE, 0xC4, 0xC8, 0xDD, 0xA1, 0xA3
  ]);
  const gbkBodyB64 = b64wrap(gbkBytes);

  return [
    'From: ' + encH('GBK用户') + ' <user@example.com>',
    'To: recipient@example.com',
    'Subject: ' + gbkSubject,
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <gbk-encoded-test@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=gbk',
    'Content-Transfer-Encoding: base64',
    '',
    gbkBodyB64
  ].join('\r\n');
}

function buildPlainBase64() {
  const text = 'This is base64 encoded plain text body for testing.\n第二行内容。';
  const body = b64wrap(Buffer.from(text, 'utf8'));

  return [
    'From: sender@example.com',
    'To: recipient@example.com',
    'Subject: Base64 Encoded Plain',
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <plain-base64@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    body
  ].join('\r\n');
}

function buildPlainQuotedPrintable() {
  const text = 'Hello World!\n这是一段需要 quoted-printable 编码的中文内容。\nLine with = sign.';
  const body = encodeQP(text);

  return [
    'From: sender@example.com',
    'To: recipient@example.com',
    'Subject: Quoted-Printable Test',
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <plain-qp@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    body
  ].join('\r\n');
}

function buildMultipartMixed() {
  const b = 'boundary_mixed_test';
  const textBody = encodeQP('请查看附件。');
  const pdfContent = Buffer.concat([Buffer.from('%PDF-1.4\n', 'latin1'), Buffer.alloc(100, 0x41)]);
  const txtContent = Buffer.from('Attachment text file content.', 'utf8');

  return [
    'From: ' + encH('发件人') + ' <sender@example.com>',
    'To: ' + encH('收件人') + ' <recipient@example.com>',
    'Subject: ' + encH('Multipart Mixed 测试'),
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <multipart-mixed@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="' + b + '"',
    '',
    '--' + b,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    textBody,
    '',
    '--' + b,
    'Content-Type: application/pdf; name="report.pdf"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="report.pdf"',
    '',
    b64wrap(pdfContent),
    '',
    '--' + b,
    'Content-Type: text/plain; name="notes.txt"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="notes.txt"',
    '',
    b64wrap(txtContent),
    '',
    '--' + b + '--'
  ].join('\r\n');
}

function buildMultipartAlternative() {
  const b = 'boundary_alt_test';
  const textBody = encodeQP('这是纯文本版本。\n\n产品新闻：\n- 更新1\n- 更新2');
  const htmlBody = encodeQP('<html><body><h1>这是 HTML 版本</h1><p>产品新闻：</p><ul><li>更新1</li><li>更新2</li></ul></body></html>');

  return [
    'From: ' + encH('运营') + ' <marketing@example.com>',
    'To: user@example.com',
    'Subject: ' + encH('Multipart Alternative 测试'),
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <multipart-alt@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/alternative; boundary="' + b + '"',
    '',
    '--' + b,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    textBody,
    '',
    '--' + b,
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    htmlBody,
    '',
    '--' + b + '--'
  ].join('\r\n');
}

function buildMultipartRelated() {
  const bRel = 'boundary_rel_test';
  const bAlt = 'boundary_alt_test';
  const logoPng = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
  const textBody = encodeQP('查看 HTML 版本以显示图片。');
  const htmlBody = encodeQP('<html><body><h1>带内联图片的邮件</h1><img src="cid:logo_cid" alt="Logo"></body></html>');

  return [
    'From: ' + encH('运营') + ' <marketing@example.com>',
    'To: user@example.com',
    'Subject: ' + encH('Multipart Related 测试'),
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <multipart-related@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/related; boundary="' + bRel + '"',
    '',
    '--' + bRel,
    'Content-Type: multipart/alternative; boundary="' + bAlt + '"',
    '',
    '--' + bAlt,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    textBody,
    '',
    '--' + bAlt,
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    htmlBody,
    '',
    '--' + bAlt + '--',
    '',
    '--' + bRel,
    'Content-Type: image/png',
    'Content-Transfer-Encoding: base64',
    'Content-ID: <logo_cid>',
    'Content-Disposition: inline; filename="logo.png"',
    '',
    b64wrap(logoPng),
    '',
    '--' + bRel + '--'
  ].join('\r\n');
}

function buildDuplicateFilenames() {
  const b = 'boundary_dup_name';
  const content1 = Buffer.from('First readme content.', 'utf8');
  const content2 = Buffer.from('Second readme content - different!', 'utf8');
  const content3 = Buffer.from('Third readme.', 'utf8');
  const textBody = encodeQP('Multiple attachments with same name.');

  return [
    'From: sender@example.com',
    'To: recipient@example.com',
    'Subject: Duplicate Filename Test',
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <dup-filenames@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="' + b + '"',
    '',
    '--' + b,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    textBody,
    '',
    '--' + b,
    'Content-Type: text/plain; name="readme.txt"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="readme.txt"',
    '',
    b64wrap(content1),
    '',
    '--' + b,
    'Content-Type: text/plain; name="readme.txt"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="readme.txt"',
    '',
    b64wrap(content2),
    '',
    '--' + b,
    'Content-Type: text/plain; name="readme.txt"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="readme.txt"',
    '',
    b64wrap(content3),
    '',
    '--' + b + '--'
  ].join('\r\n');
}

function buildExternalImages() {
  const b = 'boundary_ext_img';
  const htmlBody = encodeQP([
    '<html><body>',
    '<h1>带追踪像素的邮件</h1>',
    '<img src="https://tracker.example.com/pixel.gif?uid=123" alt="">',
    '<img src="https://cdn.example.com/banner.jpg" alt="banner">',
    '<img src="cid:local_img" alt="local">',
    '<p>点击<a href="https://phish.example.com/login">这里</a>登录</p>',
    '</body></html>'
  ].join(''));

  const logoPng = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');

  return [
    'From: ' + encH('营销') + ' <marketing@spam.com>',
    'To: user@example.com',
    'Subject: ' + encH('外部图片测试'),
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <ext-images@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/related; boundary="' + b + '"',
    '',
    '--' + b,
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    htmlBody,
    '',
    '--' + b,
    'Content-Type: image/png',
    'Content-Transfer-Encoding: base64',
    'Content-ID: <local_img>',
    'Content-Disposition: inline; filename="logo.png"',
    '',
    b64wrap(logoPng),
    '',
    '--' + b + '--'
  ].join('\r\n');
}

function buildAddressListEdge() {
  return [
    'From: "John \"The Boss\" O\'Brien" <john@example.com>',
    'To: "Alice, Smith" <alice@example.com>, <bob@example.com>, "Charlie" <charlie@example.com>, dave@example.com',
    'Cc: "Eve (Admin)" <eve@example.com> , frank@example.com',
    'Bcc: grace@example.com',
    'Reply-To: "Support Team" <support@example.com>',
    'Subject: Address List Edge Cases',
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <addr-edge@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Testing various address formats.'
  ].join('\r\n');
}

function buildMinimalHeaders() {
  return [
    'From: minimal@example.com',
    'Subject: Minimal',
    '',
    'Minimal headers body.'
  ].join('\r\n');
}

function buildEmptySubject() {
  return [
    'From: sender@example.com',
    'To: recipient@example.com',
    'Subject: ',
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <empty-subj@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Body with empty subject.'
  ].join('\r\n');
}

function buildRFC2047Mixed() {
  const subject = encH('中文') + ' and ' + encHQ('more') + ' =?ISO-8859-1?Q?B=F8lle?= mixed';
  return [
    'From: ' + encH('用户') + ' <user@example.com>',
    'To: recipient@example.com',
    'Subject: ' + subject,
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <rfc2047-mixed@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    encodeQP('RFC 2047 混合编码测试。')
  ].join('\r\n');
}

function buildForensicAuditComprehensive() {
  const b = 'boundary_forensic_audit';
  const textBody = encodeQP([
    '尊敬的用户：',
    '',
    '您的账户出现异常登录，请立即点击下方链接验证您的身份：',
    '',
    '➤ 立即验证账户: http://bit.ly/2XyZabc',
    '➤ 备用链接: https://192.168.1.100/verify?user=12345',
    '➤ 官方网站: https://www.official-bank.com.verify-phish.net/login',
    '',
    '如果您未进行操作，请立即修改密码！账户将在24小时内被删除。',
    '',
    '此致',
    '银行安全中心'
  ].join('\n'));

  const htmlBody = encodeQP([
    '<html>',
    '<head><title>安全提示</title></head>',
    '<body>',
    '<h2>账户安全警告</h2>',
    '<p>您的银行账户于今早遭遇异常登录</p>',
    '<a href="http://bit.ly/2XyZabc">立即验证账户</a>',
    '<p>备用链接: <a href="https://192.168.1.100/verify?user=12345">https://192.168.1.100/verify</a></p>',
    '<p>第三方: <a href="https://goo.gl/xyz123">短链</a></p>',
    '<p>IP直连: <a href="http://10.0.0.1/login">内网</a></p>',
    '<hr>',
    '<img src="https://tracker.phishing-scam.net/pixel.gif?email=user@example.com" alt="">',
    '<img src="https://cdn.example.com/header.png" alt="">',
    '</body>',
    '</html>'
  ].join(''));

  const attachmentTxt = Buffer.from([
    '请访问此链接: https://evil.example.com/malware',
    '备用地址: http://192.168.1.200/payload.exe',
    '短链: http://tinyurl.com/abcxyz'
  ].join('\n'), 'utf8');

  const exeContent = Buffer.from('MZ\x90\x00This program cannot be run in DOS mode.\r\r\n$', 'latin1');

  return [
    'From: =?UTF-8?B?6L6R5a625LqN6KGh?= <security@official-bank.com>',
    'Reply-To: =?UTF-8?B?5a6i5pyN5Lit5b+D?= <support@phishing-scam.net>',
    'To: =?UTF-8?B?55So5oi3?= <user@example.com>',
    'Cc: =?UTF-8?B?566h55CG5ZGY?= <admin@example.com>',
    'Bcc: =?UTF-8?B?55uR5o6n6YKu566x?= <monitor@darkside.io>',
    'Subject: =?UTF-8?B?44CQ6L6R5a6244CR5oKo55qE6LSm5oi35a6J5YWo6K2m5ZGK77yM6K+356uL5Y2z6aqM6K+B?=',
    'Date: Mon, 20 Jan 2025 09:30:00 +0000',
    'Message-ID: <20250120.abc123@192.168.1.100>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="' + b + '"',
    'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=official-bank.com;',
    ' s=default; t=1705743000;',
    ' bh=abcdefghijklmnopqrstuvwxyz1234567890=;',
    ' b=FakeDkimSignatureForTesting=',
    'Received-SPF: none (google.com: 192.168.1.100 does not designate permitted sender hosts)',
    'Authentication-Results: mx.google.com;',
    ' dkim=pass header.i=@official-bank.com header.s=default header.b=fake;',
    ' spf=none smtp.mailfrom=security@official-bank.com;',
    ' dmarc=fail p=quarantine dis=none header.from=official-bank.com',
    'X-Mailer: PHPMailer 5.2.23 (https://github.com/PHPMailer/PHPMailer)',
    'X-Priority: 1 (Highest)',
    'Importance: High',
    'Priority: urgent',
    'Received: from mail.evil-server.net (mail.evil-server.net [203.0.113.45])',
    '  by mx.google.com with ESMTPS id abc123def456',
    '  for <user@example.com>;',
    '  Tue, 21 Jan 2025 10:15:30 +0800 (CST)',
    'Received: from [192.168.1.100] (unknown [198.51.100.23])',
    '  by mail.evil-server.net (Postfix) with ESMTP id ABC123DEF456',
    '  for <user@example.com>;',
    '  Tue, 21 Jan 2025 02:12:45 +0000 (UTC)',
    'Received: from localhost (localhost [127.0.0.1])',
    '  by internal.evil-server.net with ESMTP id XYZ789012',
    '  for <user@example.com>;',
    '  Tue, 21 Jan 2025 02:10:00 +0000 (UTC)',
    '',
    '--' + b,
    'Content-Type: multipart/alternative; boundary="inner_alt"',
    '',
    '--inner_alt',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    textBody,
    '',
    '--inner_alt',
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    htmlBody,
    '',
    '--inner_alt--',
    '',
    '--' + b,
    'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="invoice.pdf.exe"',
    '',
    b64wrap(exeContent),
    '',
    '--' + b,
    'Content-Type: text/plain; name="links.txt"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="links.txt"',
    '',
    b64wrap(attachmentTxt),
    '',
    '--' + b + '--'
  ].join('\r\n');
}

function buildRFC2231Filename() {
  const b = 'boundary_rfc2231';
  const content = Buffer.from('RFC 2231 filename test content.', 'utf8');
  // RFC 2231: filename*=utf-8''%E4%B8%AD%E6%96%87.pdf
  return [
    'From: sender@example.com',
    'To: recipient@example.com',
    'Subject: RFC 2231 Filename',
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'Message-ID: <rfc2231-filename@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="' + b + '"',
    '',
    '--' + b,
    'Content-Type: text/plain; charset=utf-8',
    '',
    'RFC 2231 test body.',
    '',
    '--' + b,
    'Content-Type: application/pdf',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename*=utf-8\'\'%E4%B8%AD%E6%96%87%E6%96%87%E4%BB%B6.pdf',
    '',
    b64wrap(content),
    '',
    '--' + b + '--'
  ].join('\r\n');
}

function buildMissingMessageId() {
  return [
    'From: sender@example.com',
    'To: recipient@example.com',
    'Subject: No Message-ID',
    'Date: Mon, 20 Jan 2025 10:30:00 +0800',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Body without Message-ID.'
  ].join('\r\n');
}

console.log('\nGenerating test EML samples to test/samples/...\n');

writeEml('01_header_crlf.eml', buildHeaderEndCRLF());
writeEml('02_header_lf.eml', buildHeaderEndLF());
writeEml('03_folded_headers.eml', buildFoldedHeader());
writeEml('04_gbk_encoded.eml', buildGBKEncoded());
writeEml('05_plain_base64.eml', buildPlainBase64());
writeEml('06_plain_qp.eml', buildPlainQuotedPrintable());
writeEml('07_multipart_mixed.eml', buildMultipartMixed());
writeEml('08_multipart_alternative.eml', buildMultipartAlternative());
writeEml('09_multipart_related.eml', buildMultipartRelated());
writeEml('10_duplicate_filenames.eml', buildDuplicateFilenames());
writeEml('11_external_images.eml', buildExternalImages());
writeEml('12_address_edge.eml', buildAddressListEdge());
writeEml('13_minimal_headers.eml', buildMinimalHeaders());
writeEml('14_empty_subject.eml', buildEmptySubject());
writeEml('15_rfc2047_mixed.eml', buildRFC2047Mixed());
writeEml('16_forensic_audit.eml', buildForensicAuditComprehensive());
writeEml('17_rfc2231_filename.eml', buildRFC2231Filename());
writeEml('18_missing_messageid.eml', buildMissingMessageId());

// Also copy the original samples
const origSamples = path.join(__dirname, '..', 'samples');
if (fs.existsSync(origSamples)) {
  for (const f of fs.readdirSync(origSamples)) {
    if (f.endsWith('.eml')) {
      const src = path.join(origSamples, f);
      const dst = path.join(OUT_DIR, 'orig_' + f);
      fs.copyFileSync(src, dst);
      console.log('✓ orig_' + f + ' (copied)');
    }
  }
}

console.log('\n✓ All test samples generated.');
