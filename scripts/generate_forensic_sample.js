const fs = require('fs');
const path = require('path');

const textContent = `尊敬的客户：

您的银行账户出现异常登录，请立即点击下方链接验证您的身份：

➤ 立即验证账户: http://bit.ly/2XyZabc
➤ 备用链接: https://192.168.1.100/verify?user=12345
➤ 官方网站: https://www.official-bank.com.verify-phish.net/login

如果您未进行操作，请立即修改密码！账户将在24小时内被删除。

此致
银行安全中心`;

const htmlContent = `<html>
<head>
  <title>安全提示</title>
</head>
<body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 5px;">
    <div style="text-align: center; margin-bottom: 20px;">
      <img src="https://www.official-bank.com.verify-phish.net/images/logo.png" alt="Bank Logo" style="width: 150px;">
    </div>
    <h2 style="color: #d32f2f; text-align: center;">账户安全警告</h2>
    <p>您的银行账户于今早遭遇异常登录。</p>
    <p>为了您的账户安全，请立即验证您的身份：</p>
    <div style="text-align: center; margin: 30px 0;">
      <a href="http://bit.ly/2XyZabc" style="display: inline-block; padding: 15px 30px; background: #d32f2f; color: white; text-decoration: none; border-radius: 5px; font-size: 18px;">
        立即验证账户
      </a>
    </div>
    <p>备用链接: <a href="https://192.168.1.100/verify?user=12345">https://192.168.1.100/verify</a></p>
    <p>如有疑问，请回复本邮件或联系客服。</p>
    <hr>
    <p style="font-size: 12px; color: #999;">
      本邮件系系统自动发送，请勿直接回复。
      <br>
      <img src="https://tracker.phishing-scam.net/pixel.gif?email=user@example.com" alt="" style="width: 1px; height: 1px;">
    </p>
  </div>
</body>
</html>`;

function encodeQuotedPrintable(str) {
  const buf = Buffer.from(str, 'utf8');
  let result = '';
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    if (byte > 126 || byte === 61 || byte === 9 || (byte < 32 && byte !== 10 && byte !== 13)) {
      result += '=' + byte.toString(16).toUpperCase().padStart(2, '0');
    } else {
      result += String.fromCharCode(byte);
    }
  }

  const lines = [];
  let currentLine = '';
  let i = 0;
  while (i < result.length) {
    if (result[i] === '\r' && result[i + 1] === '\n') {
      lines.push(currentLine);
      currentLine = '';
      i += 2;
    } else if (result[i] === '\n') {
      lines.push(currentLine);
      currentLine = '';
      i += 1;
    } else {
      currentLine += result[i];
      i++;
    }

    if (currentLine.length >= 74) {
      const lastEqual = currentLine.lastIndexOf('=', 73);
      if (lastEqual >= 72) {
        lines.push(currentLine.substring(0, lastEqual));
        currentLine = currentLine.substring(lastEqual);
      } else {
        lines.push(currentLine + '=');
        currentLine = '';
      }
    }
  }
  if (currentLine) lines.push(currentLine);
  return lines.join('\r\n');
}

function encodeHeader(str, charset = 'UTF-8') {
  if (/^[\x00-\x7F]*$/.test(str)) return str;
  const encoded = Buffer.from(str, 'utf8').toString('base64');
  return `=?${charset}?B?${encoded}?=`;
}

const subject = '【紧急】您的账户安全警告，请立即验证';
const fromName = '安全中心';
const toName = '用户';
const ccName = '管理员';
const bccName = '监控邮箱';
const replyToName = '客服中心';

const textQp = encodeQuotedPrintable(textContent);
const htmlQp = encodeQuotedPrintable(htmlContent);

const emlContent = `From: ${encodeHeader(fromName)} <security@official-bank.com>
Reply-To: ${encodeHeader(replyToName)} <support@phishing-scam.net>
To: ${encodeHeader(toName)} <user@example.com>
Cc: ${encodeHeader(ccName)} <admin@example.com>
Bcc: ${encodeHeader(bccName)} <monitor@darkside.io>
Subject: ${encodeHeader(subject)}
Date: Mon, 20 Jan 2025 09:30:00 +0000
Message-ID: <20250120.abc123@192.168.1.100>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary_forensic_005"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=official-bank.com;
 s=default; t=1705743000;
 bh=abcdefghijklmnopqrstuvwxyz1234567890=;
 b=FakeDkimSignatureThatIsNotRealButLooksPlausibleForTesting=
Received-SPF: none (google.com: 192.168.1.100 does not designate permitted sender hosts)
Authentication-Results: mx.google.com;
 dkim=pass header.i=@official-bank.com header.s=default header.b=fake;
 spf=none smtp.mailfrom=security@official-bank.com;
 dmarc=fail p=quarantine dis=none header.from=official-bank.com
X-Mailer: PHPMailer 5.2.23 (https://github.com/PHPMailer/PHPMailer)
X-Priority: 1 (Highest)
Importance: High
Priority: urgent
Received: from mail.evil-server.net (mail.evil-server.net [203.0.113.45])
 by mx.google.com with ESMTPS id abc123def456
 for <user@example.com>;
 Tue, 21 Jan 2025 10:15:30 +0800 (CST)
Received: from [192.168.1.100] (unknown [198.51.100.23])
 by mail.evil-server.net (Postfix) with ESMTP id ABC123DEF456
 for <user@example.com>;
 Tue, 21 Jan 2025 02:12:45 +0000 (UTC)
Received: from localhost (localhost [127.0.0.1])
 by internal.evil-server.net with ESMTP id XYZ789012
 for <user@example.com>;
 Tue, 21 Jan 2025 02:10:00 +0000 (UTC)

--boundary_forensic_005
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

${textQp}

--boundary_forensic_005
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

${htmlQp}

--boundary_forensic_005--
`;

const outputPath = path.join(__dirname, '..', 'samples', 'sample5_forensic.eml');
fs.writeFileSync(outputPath, emlContent, 'utf8');
console.log(`Forensic sample generated: ${outputPath}`);
