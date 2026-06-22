const path = require('path');
const { extractExternalImageUrls } = require('./bodyExtractor');
const { findAllAttachments, getFileExtension } = require('./attachmentExtractor');

const SUSPICIOUS_EXTENSIONS = [
  '.exe', '.com', '.bat', '.cmd', '.pif', '.scr', '.vbs', '.js', '.jse',
  '.wsf', '.wsh', '.ps1', '.psm1', '.psd1', '.sh', '.bash', '.zsh',
  '.msi', '.msp', '.mst', '.reg', '.dll', '.sys', '.drv',
  '.hta', '.cpl', '.jar', '.class', '.apk', '.ipa'
];

const MACRO_ENABLED_EXTENSIONS = [
  '.docm', '.dotm', '.xlsm', '.xltm', '.xlam', '.pptm', '.potm',
  '.ppam', '.ppsm', '.sldm', '.mdb', '.accde', '.accdr'
];

const OFFICE_EXTENSIONS = [
  '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.odt', '.ods', '.odp', '.rtf'
];

const MAX_ATTACHMENT_SIZE = 20 * 1024 * 1024;
const VERY_LARGE_ATTACHMENT_SIZE = 50 * 1024 * 1024;

const RISK_LEVELS = {
  SAFE: 'safe',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

function checkSecurity(emlData, options = {}) {
  const issues = [];
  let overallRisk = RISK_LEVELS.SAFE;

  const attachmentCheck = checkAttachments(emlData.attachments, options);
  issues.push(...attachmentCheck.issues);

  const externalImageCheck = checkExternalImages(emlData);
  issues.push(...externalImageCheck.issues);

  const doubleExtensionCheck = checkDoubleExtensions(emlData.attachments);
  issues.push(...doubleExtensionCheck.issues);

  const headerCheck = checkHeaders(emlData);
  issues.push(...headerCheck.issues);

  for (const issue of issues) {
    if (compareRiskLevels(issue.risk, overallRisk) > 0) {
      overallRisk = issue.risk;
    }
  }

  return {
    overallRisk,
    riskLevel: getRiskLevelText(overallRisk),
    issues,
    summary: {
      total: issues.length,
      critical: issues.filter(i => i.risk === RISK_LEVELS.CRITICAL).length,
      high: issues.filter(i => i.risk === RISK_LEVELS.HIGH).length,
      medium: issues.filter(i => i.risk === RISK_LEVELS.MEDIUM).length,
      low: issues.filter(i => i.risk === RISK_LEVELS.LOW).length,
      safe: issues.filter(i => i.risk === RISK_LEVELS.SAFE).length
    }
  };
}

function checkAttachments(attachments, options = {}) {
  const issues = [];
  const maxSize = options.maxSize || MAX_ATTACHMENT_SIZE;

  for (const att of attachments) {
    const ext = att.extension ? att.extension.toLowerCase() : '';

    if (SUSPICIOUS_EXTENSIONS.includes(ext)) {
      issues.push({
        type: 'suspicious_extension',
        risk: RISK_LEVELS.HIGH,
        severity: 'high',
        attachment: att.filename,
        description: `附件 ${att.filename} 使用了可疑的可执行文件扩展名 ${ext}`,
        details: {
          filename: att.filename,
          extension: ext,
          category: 'executable'
        }
      });
    }

    if (MACRO_ENABLED_EXTENSIONS.includes(ext)) {
      issues.push({
        type: 'macro_enabled',
        risk: RISK_LEVELS.HIGH,
        severity: 'high',
        attachment: att.filename,
        description: `附件 ${att.filename} 是启用宏的 Office 文档，可能包含恶意宏`,
        details: {
          filename: att.filename,
          extension: ext,
          category: 'macro'
        }
      });
    }

    if (att.size > maxSize) {
      const risk = att.size > VERY_LARGE_ATTACHMENT_SIZE ? RISK_LEVELS.MEDIUM : RISK_LEVELS.LOW;
      issues.push({
        type: 'oversized_attachment',
        risk,
        severity: risk === RISK_LEVELS.MEDIUM ? 'medium' : 'low',
        attachment: att.filename,
        description: `附件 ${att.filename} 体积较大 (${formatSize(att.size)})`,
        details: {
          filename: att.filename,
          size: att.size,
          sizeFormatted: formatSize(att.size),
          maxSize: maxSize
        }
      });
    }
  }

  return { issues };
}

function checkExternalImages(emlData) {
  const issues = [];

  if (!emlData.bodies || !emlData.bodies.html) {
    return { issues };
  }

  const externalUrls = extractExternalImageUrls(emlData.bodies.html);

  if (externalUrls.length > 0) {
    issues.push({
      type: 'external_images',
      risk: RISK_LEVELS.LOW,
      severity: 'low',
      description: `HTML 正文中包含 ${externalUrls.length} 张外部图片，可能用于追踪`,
      details: {
        count: externalUrls.length,
        urls: externalUrls
      }
    });
  }

  return { issues };
}

function checkDoubleExtensions(attachments) {
  const issues = [];

  for (const att of attachments) {
    const filename = att.filename || '';
    const parts = filename.split('.');

    if (parts.length >= 3) {
      const lastExt = '.' + parts[parts.length - 1].toLowerCase();
      const secondLastExt = '.' + parts[parts.length - 2].toLowerCase();

      const isDocExt = OFFICE_EXTENSIONS.includes(secondLastExt) || ['.txt', '.pdf', '.jpg', '.png', '.gif', '.doc', '.docx', '.xls', '.xlsx'].includes(secondLastExt);
      const isSuspiciousExt = SUSPICIOUS_EXTENSIONS.includes(lastExt) || MACRO_ENABLED_EXTENSIONS.includes(lastExt);

      if (isDocExt && isSuspiciousExt) {
        issues.push({
          type: 'double_extension',
          risk: RISK_LEVELS.CRITICAL,
          severity: 'critical',
          attachment: att.filename,
          description: `附件 ${att.filename} 疑似双扩展名伪装，可能是恶意文件`,
          details: {
            filename: att.filename,
            visibleExtension: secondLastExt,
            actualExtension: lastExt,
            category: 'disguise'
          }
        });
      }
    }
  }

  return { issues };
}

function checkHeaders(emlData) {
  const issues = [];
  const headers = emlData.headers;

  if (!headers) return { issues };

  if (headers.from && headers.from.email) {
    const fromDomain = headers.from.email.split('@')[1];
    if (fromDomain) {
      if (fromDomain.match(/\[.*\]/)) {
        issues.push({
          type: 'ip_based_sender',
          risk: RISK_LEVELS.LOW,
          description: '发件人使用 IP 地址域名，较为可疑',
          details: { from: headers.from.email }
        });
      }
    }
  }

  if (headers.allHeaders && headers.allHeaders['x-mailer']) {
    const xMailer = headers.allHeaders['x-mailer'][0] || '';
    if (xMailer.toLowerCase().includes('php') || xMailer.toLowerCase().includes('mass')) {
      issues.push({
        type: 'bulk_mailer',
        risk: RISK_LEVELS.LOW,
        description: '邮件由批量邮件工具发送，可能是垃圾邮件',
        details: { xMailer }
      });
    }
  }

  return { issues };
}

function compareRiskLevels(level1, level2) {
  const order = [
    RISK_LEVELS.SAFE,
    RISK_LEVELS.LOW,
    RISK_LEVELS.MEDIUM,
    RISK_LEVELS.HIGH,
    RISK_LEVELS.CRITICAL
  ];
  return order.indexOf(level1) - order.indexOf(level2);
}

function getRiskLevelText(level) {
  const texts = {
    [RISK_LEVELS.SAFE]: '安全',
    [RISK_LEVELS.LOW]: '低风险',
    [RISK_LEVELS.MEDIUM]: '中风险',
    [RISK_LEVELS.HIGH]: '高风险',
    [RISK_LEVELS.CRITICAL]: '严重风险'
  };
  return texts[level] || level;
}

function getRiskColor(level) {
  const colors = {
    [RISK_LEVELS.SAFE]: 'green',
    [RISK_LEVELS.LOW]: 'yellow',
    [RISK_LEVELS.MEDIUM]: 'orange',
    [RISK_LEVELS.HIGH]: 'red',
    [RISK_LEVELS.CRITICAL]: 'red'
  };
  return colors[level] || 'gray';
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

module.exports = {
  checkSecurity,
  RISK_LEVELS,
  SUSPICIOUS_EXTENSIONS,
  MACRO_ENABLED_EXTENSIONS,
  getRiskLevelText,
  getRiskColor
};
