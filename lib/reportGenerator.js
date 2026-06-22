const fs = require('fs');
const path = require('path');
const { formatMimeTree, formatSize } = require('./mimeParser');
const { getBodySummary } = require('./bodyExtractor');
const { getRiskLevelText } = require('./securityChecker');

function generateReport(emlData, format = 'json') {
  if (format.toLowerCase() === 'markdown' || format.toLowerCase() === 'md') {
    return generateMarkdownReport(emlData);
  }
  return generateJsonReport(emlData);
}

function generateJsonReport(emlData) {
  const report = {
    generatedAt: new Date().toISOString(),
    file: emlData.file || '',
    headers: {
      from: emlData.headers.from,
      to: emlData.headers.to,
      cc: emlData.headers.cc,
      bcc: emlData.headers.bcc,
      replyTo: emlData.headers.replyTo,
      subject: emlData.headers.subject,
      date: emlData.headers.date ? emlData.headers.date.toISOString() : null,
      dateString: emlData.headers.dateString,
      messageId: emlData.headers.messageId,
      mimeVersion: emlData.headers.mimeVersion
    },
    mimeTree: formatMimeTreeForJson(emlData.mimeTree),
    body: {
      text: emlData.bodies.text || null,
      html: emlData.bodies.html ? true : false,
      summary: getBodySummary(emlData.bodies.text || emlData.bodies.htmlAsText || '', 500),
      plainTextSize: emlData.bodies.text ? Buffer.byteLength(emlData.bodies.text, 'utf8') : 0,
      htmlSize: emlData.bodies.html ? Buffer.byteLength(emlData.bodies.html, 'utf8') : 0
    },
    attachments: emlData.attachments.map(att => ({
      filename: att.filename,
      contentType: att.contentType,
      size: att.size,
      sizeFormatted: att.sizeFormatted,
      contentId: att.contentId,
      contentDisposition: att.contentDisposition,
      sha256: att.sha256,
      isInline: att.isInline
    })),
    security: emlData.security
  };

  return JSON.stringify(report, null, 2);
}

function formatMimeTreeForJson(node) {
  return {
    contentType: node.contentType,
    charset: node.charset,
    contentTransferEncoding: node.contentTransferEncoding,
    contentDisposition: node.contentDisposition,
    filename: node.filename,
    contentId: node.contentId,
    size: node.size,
    sizeFormatted: formatSize(node.size),
    children: node.children ? node.children.map(child => formatMimeTreeForJson(child)) : []
  };
}

function generateMarkdownReport(emlData) {
  let md = '';

  md += '# 邮件分析报告\n\n';
  md += `> 生成时间: ${new Date().toLocaleString('zh-CN')}\n`;
  if (emlData.file) {
    md += `> 文件: ${path.basename(emlData.file)}\n`;
  }
  md += '\n---\n\n';

  md += '## 一、邮件头信息\n\n';

  if (emlData.headers.from) {
    md += `- **发件人 (From):** ${formatAddress(emlData.headers.from)}\n`;
  }

  if (emlData.headers.to && emlData.headers.to.length > 0) {
    md += `- **收件人 (To):** ${emlData.headers.to.map(a => formatAddress(a)).join(', ')}\n`;
  }

  if (emlData.headers.cc && emlData.headers.cc.length > 0) {
    md += `- **抄送 (Cc):** ${emlData.headers.cc.map(a => formatAddress(a)).join(', ')}\n`;
  }

  if (emlData.headers.replyTo && emlData.headers.replyTo.length > 0) {
    md += `- **回复 (Reply-To):** ${emlData.headers.replyTo.map(a => formatAddress(a)).join(', ')}\n`;
  }

  md += `- **主题 (Subject):** ${emlData.headers.subject || '(无主题)'}\n`;
  md += `- **日期 (Date):** ${emlData.headers.dateString || '(无)'}\n`;
  md += `- **Message-ID:** ${emlData.headers.messageId || '(无)'}\n`;
  md += `- **MIME 版本:** ${emlData.headers.mimeVersion || '(无)'}\n`;

  md += '\n---\n\n';

  md += '## 二、MIME 结构\n\n';
  md += '```\n';
  const mimeTreeLines = formatMimeTree(emlData.mimeTree);
  md += mimeTreeLines.join('\n') + '\n';
  md += '```\n\n';

  md += '---\n\n';

  md += '## 三、正文摘要\n\n';

  md += `- **纯文本正文:** ${emlData.bodies.text ? '有' : '无'} `;
  if (emlData.bodies.text) {
    md += `(${formatSize(Buffer.byteLength(emlData.bodies.text, 'utf8'))})`;
  }
  md += '\n';

  md += `- **HTML 正文:** ${emlData.bodies.html ? '有' : '无'} `;
  if (emlData.bodies.html) {
    md += `(${formatSize(Buffer.byteLength(emlData.bodies.html, 'utf8'))})`;
  }
  md += '\n\n';

  md += '**正文摘要:**\n\n';
  const summary = getBodySummary(emlData.bodies.text || emlData.bodies.htmlAsText || '', 500);
  md += '> ' + summary.replace(/\n/g, '\n> ') + '\n\n';

  md += '---\n\n';

  md += '## 四、附件列表\n\n';

  if (emlData.attachments.length === 0) {
    md += '*无附件*\n\n';
  } else {
    md += '| 序号 | 文件名 | 类型 | 大小 | Content-ID | SHA256 |\n';
    md += '|------|--------|------|------|------------|--------|\n';

    emlData.attachments.forEach((att, index) => {
      md += `| ${index + 1} | ${att.filename} | ${att.contentType} | ${att.sizeFormatted} | ${att.contentId || '-'} | \`${att.sha256.substring(0, 16)}...\` |\n`;
    });

    md += '\n';
  }

  md += '---\n\n';

  md += '## 五、安全风险分析\n\n';

  const sec = emlData.security;
  const riskBadge = getRiskBadge(sec.overallRisk);
  md += `### 总体风险等级: ${riskBadge}\n\n`;

  if (sec.issues.length === 0) {
    md += '*未发现安全风险*\n\n';
  } else {
    md += `共发现 **${sec.issues.length}** 个安全问题:\n\n`;

    for (let i = 0; i < sec.issues.length; i++) {
      const issue = sec.issues[i];
      const badge = getRiskBadge(issue.risk);
      md += `#### ${i + 1}. ${badge} - ${issue.description}\n\n`;

      if (issue.details) {
        md += '**详情:**\n\n';
        for (const [key, value] of Object.entries(issue.details)) {
          if (Array.isArray(value)) {
            md += `- ${key}: \n`;
            value.forEach(v => md += `  - ${v}\n`);
          } else if (typeof value === 'object') {
            md += `- ${key}: ${JSON.stringify(value)}\n`;
          } else {
            md += `- ${key}: ${value}\n`;
          }
        }
        md += '\n';
      }
    }
  }

  return md;
}

function formatAddress(addr) {
  if (!addr) return '';
  if (addr.name && addr.email) {
    return `${addr.name} <${addr.email}>`;
  }
  return addr.email || '';
}

function getRiskBadge(level) {
  const badges = {
    safe: '🟢 **安全**',
    low: '🟡 **低风险**',
    medium: '🟠 **中风险**',
    high: '🔴 **高风险**',
    critical: '💀 **严重风险**'
  };
  return badges[level] || `**${level}**`;
}

function exportReport(emlData, outputPath) {
  const ext = path.extname(outputPath).toLowerCase();
  let content;

  if (ext === '.md' || ext === '.markdown') {
    content = generateMarkdownReport(emlData);
  } else {
    content = generateJsonReport(emlData);
  }

  fs.writeFileSync(outputPath, content, 'utf8');
  return { path: outputPath, format: ext === '.md' || ext === '.markdown' ? 'markdown' : 'json' };
}

module.exports = {
  generateReport,
  generateJsonReport,
  generateMarkdownReport,
  exportReport
};
