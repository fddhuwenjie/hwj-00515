const fs = require('fs');
const path = require('path');

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

function encH(s) {
  return '=?UTF-8?B?' + Buffer.from(s, 'utf8').toString('base64') + '?=';
}

function b64wrap(b) {
  return b.toString('base64').match(/.{1,72}/g).join('\n');
}

const outDir = path.join(__dirname, '..', 'samples');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

// ===== Sample 1: 纯文本 =====
const body1 = `你好！

这是一封纯文本测试邮件，用于测试 EML 解析功能。

内容包括：
  1. 第一条内容
  2. 第二条内容
  3. 第三条内容

此致敬礼

张三
2025年1月20日
`;

const eml1 = `From: ${encH('张三')} <zhangsan@example.com>
To: ${encH('李四')} <lisi@example.com>, wangwu@example.com
Cc: ${encH('赵六')} <zhaoliu@example.com>
Reply-To: ${encH('张三')} <zhangsan@example.com>
Subject: ${encH('你好，这是一封纯文本测试邮件')}
Date: Mon, 20 Jan 2025 10:30:00 +0800
Message-ID: <plain-email-001@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

${encodeQP(body1)}
`;

fs.writeFileSync(path.join(outDir, 'sample1_plain.eml'), eml1, 'latin1');
console.log('✓ sample1_plain.eml');

// ===== Sample 2: HTML + 内联图 =====
const textBody2 = '产品新闻通讯\n\n本期新闻要点：\n- 功能更新\n- 性能优化\n- 用户反馈\n\n详情请登录官网查看。\n';
const htmlBody2 = '<html><body><h1>产品新闻通讯</h1><p>亲爱的用户：</p><ul><li><b>功能更新</b> - 新增多项实用功能</li><li><b>性能优化</b> - 加速20%</li></ul><img src="cid:logo_image" alt="Logo"><img src="https://example.com/tracker.gif" style="width:1px;height:1px;"></body></html>';
const logoPng = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');

const bAlt = 'boundary_alt_002';
const bRel = 'boundary_rel_002';

const eml2 = `From: ${encH('产品运营')} <marketing@example.com>
To: ${encH('用户')} <user@example.com>
Subject: ${encH('产品新闻通讯')}
Date: Tue, 21 Jan 2025 14:00:00 +0800
Message-ID: <html-inline-002@example.com>
MIME-Version: 1.0
Content-Type: multipart/related; boundary="${bRel}"

--${bRel}
Content-Type: multipart/alternative; boundary="${bAlt}"

--${bAlt}
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

${encodeQP(textBody2)}

--${bAlt}
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

${encodeQP(htmlBody2)}

--${bAlt}--

--${bRel}
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: <logo_image>
Content-Disposition: inline; filename="logo.png"

${b64wrap(logoPng)}

--${bRel}--
`;

fs.writeFileSync(path.join(outDir, 'sample2_html_inline.eml'), eml2, 'latin1');
console.log('✓ sample2_html_inline.eml');

// ===== Sample 3: 多个附件 =====
const png = Buffer.concat([Buffer.from([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]), Buffer.alloc(200, 0x42)]);
const pdf = Buffer.concat([Buffer.from('%PDF-1.4\n', 'latin1'), Buffer.alloc(500, 0x41)]);
const docx = Buffer.concat([Buffer.from([0x50,0x4B,0x03,0x04]), Buffer.alloc(300, 0x44)]);
const b3 = 'boundary_mixed_003';
const t3 = '您好：\n\n附件是本周项目相关资料，请查收。\n\n包含内容：\n1. 项目报告 PDF\n2. 需求文档\n3. 产品截图\n\n谢谢！\n';

const eml3 = `From: ${encH('项目经理')} <pm@example.com>
To: ${encH('团队成员')} <team@example.com>
Subject: ${encH('项目资料 - 多个附件')}
Date: Wed, 22 Jan 2025 09:15:00 +0800
Message-ID: <multi-attach-003@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="${b3}"

--${b3}
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

${encodeQP(t3)}

--${b3}
Content-Type: application/pdf; name="${encH('项目报告')}.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="${encH('项目报告')}.pdf"

${b64wrap(pdf)}

--${b3}
Content-Type: image/png; name="screenshot.png"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="screenshot.png"

${b64wrap(png)}

--${b3}
Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document; name="${encH('需求文档')}.docx"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="${encH('需求文档')}.docx"

${b64wrap(docx)}

--${b3}--
`;

fs.writeFileSync(path.join(outDir, 'sample3_multi_attach.eml'), eml3, 'latin1');
console.log('✓ sample3_multi_attach.eml');

// ===== Sample 4: 可疑附件 =====
const exe = Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21This program cannot be run in DOS mode.\r\r\n$', 'latin1');
const docm = Buffer.concat([Buffer.from('PK\x03\x04\x14\x00\x06\x00fake-docm-with-macros-vba'), Buffer.alloc(200, 0x4D)]);
const b4 = 'boundary_mixed_004';
const t4 = '尊敬的客户：\n\n请查看附件中的发票，如无疑问请尽快付款。\n\n  财务部门\n';

const eml4 = `From: ${encH('财务部门')} <finance@fake-bank.com>
To: ${encH('客户')} <victim@example.com>
Subject: ${encH('【紧急】请查看发票')}
Date: Thu, 23 Jan 2025 16:45:00 +0800
Message-ID: <suspicious-004@scammer.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="${b4}"

--${b4}
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

${encodeQP(t4)}

--${b4}
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice.pdf.exe"

${b64wrap(exe)}

--${b4}
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="${encH('重要通知')}.docm"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="${encH('重要通知')}.docm"

${b64wrap(docm)}

--${b4}--
`;

fs.writeFileSync(path.join(outDir, 'sample4_suspicious.eml'), eml4, 'latin1');
console.log('✓ sample4_suspicious.eml');

console.log('\n全部 4 封示例邮件已生成到 samples/ 目录');
