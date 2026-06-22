const { decodeContent, flattenMimeTree, formatSize } = require('./mimeParser');
const { extractExternalImageUrls, htmlToPlainText } = require('./bodyExtractor');
const { findAllAttachments, getFileExtension } = require('./attachmentExtractor');
const { RISK_LEVELS, getRiskLevelText } = require('./securityChecker');

const SHORT_URL_DOMAINS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cli.gs',
  'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu',
  'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to',
  ' Budurl.com', 'Snurl.com', 'TweetPhoto.com', 'post.ly',
  'x.co', '1url.com', 'adf.ly', 'ow.ly', 'j.mp', 'bkite.com'
];

function runForensicAudit(emlData) {
  const audit = {
    generatedAt: new Date().toISOString(),
    file: emlData.file || '',
    headers: auditHeaders(emlData),
    receivedChain: analyzeReceivedChain(emlData),
    suspiciousSignals: detectSuspiciousSignals(emlData),
    urls: extractAndAnalyzeUrls(emlData),
    authenticationResults: analyzeAuthenticationResults(emlData),
    attachmentsAudit: auditAttachments(emlData),
    overallRisk: 'safe',
    signalSummary: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    }
  };

  const allSignals = audit.suspiciousSignals;
  audit.signalSummary.total = allSignals.length;
  audit.signalSummary.critical = allSignals.filter(s => s.risk === 'critical').length;
  audit.signalSummary.high = allSignals.filter(s => s.risk === 'high').length;
  audit.signalSummary.medium = allSignals.filter(s => s.risk === 'medium').length;
  audit.signalSummary.low = allSignals.filter(s => s.risk === 'low').length;

  let overall = 'safe';
  for (const signal of allSignals) {
    if (compareRisk(signal.risk, overall) > 0) {
      overall = signal.risk;
    }
  }
  audit.overallRisk = overall;
  audit.overallRiskText = getRiskLevelText(overall);

  return audit;
}

function auditHeaders(emlData) {
  const h = emlData.headers;
  return {
    from: h.from || null,
    fromDomain: h.from && h.from.email ? h.from.email.split('@')[1] : null,
    to: h.to || [],
    cc: h.cc || [],
    bcc: h.bcc || [],
    replyTo: h.replyTo || [],
    replyToDomain: h.replyTo && h.replyTo.length > 0 && h.replyTo[0].email
      ? h.replyTo[0].email.split('@')[1]
      : null,
    subject: h.subject || '',
    date: h.date ? h.date.toISOString() : null,
    dateString: h.dateString || '',
    messageId: h.messageId || '',
    messageIdDomain: extractMessageIdDomain(h.messageId),
    mimeVersion: h.mimeVersion || '',
    allHeaders: h.allHeaders || {}
  };
}

function extractMessageIdDomain(messageId) {
  if (!messageId) return null;
  const match = messageId.match(/@([^>]+)/);
  return match ? match[1] : null;
}

function analyzeReceivedChain(emlData) {
  const allHeaders = emlData.headers.allHeaders || {};
  const receivedHeaders = allHeaders['received'] || [];

  const hops = receivedHeaders.map((raw, index) => parseReceivedHeader(raw, index));

  const validHops = hops.filter(h => h !== null);

  validHops.sort((a, b) => {
    if (!a.date) return 1;
    if (!b.date) return -1;
    return new Date(b.date) - new Date(a.date);
  });

  for (let i = 0; i < validHops.length - 1; i++) {
    const current = validHops[i];
    const next = validHops[i + 1];
    if (current.date && next.date) {
      const diffMs = new Date(current.date) - new Date(next.date);
      current.delaySeconds = Math.round(diffMs / 1000);
      current.delayFormatted = formatDelay(diffMs);
    } else {
      current.delaySeconds = null;
      current.delayFormatted = null;
    }
  }

  if (validHops.length > 0) {
    const last = validHops[validHops.length - 1];
    last.delaySeconds = null;
    last.delayFormatted = null;
  }

  return {
    count: validHops.length,
    hops: validHops
  };
}

function parseReceivedHeader(raw, index) {
  if (!raw) return null;

  const result = {
    index,
    raw,
    from: null,
    fromIp: null,
    by: null,
    with: null,
    id: null,
    for: null,
    date: null,
    dateString: null
  };

  const dateMatch = raw.match(/;\s*([^;]+)\s*$/);
  if (dateMatch) {
    result.dateString = dateMatch[1].trim();
    const parsedDate = new Date(result.dateString);
    if (!isNaN(parsedDate.getTime())) {
      result.date = parsedDate.toISOString();
    }
  }

  const fromMatch = raw.match(/from\s+([^\s]+(?:\s+\([^)]+\))?)/i);
  if (fromMatch) {
    result.from = fromMatch[1].trim();
    const ipMatch = fromMatch[0].match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
    if (ipMatch) {
      result.fromIp = ipMatch[1];
    }
  }

  const byMatch = raw.match(/by\s+([^\s]+)/i);
  if (byMatch) {
    result.by = byMatch[1];
  }

  const withMatch = raw.match(/with\s+([a-z0-9_-]+)/i);
  if (withMatch) {
    result.with = withMatch[1];
  }

  const idMatch = raw.match(/id\s+([^\s;]+)/i);
  if (idMatch) {
    result.id = idMatch[1];
  }

  const forMatch = raw.match(/for\s+<([^>]+)>/i);
  if (forMatch) {
    result.for = forMatch[1];
  }

  return result;
}

function formatDelay(ms) {
  if (ms < 0) ms = 0;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  if (minutes < 60) return `${minutes} 分 ${remainingSeconds} 秒`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return `${hours} 小时 ${remainingMinutes} 分`;
}

function detectSuspiciousSignals(emlData) {
  const signals = [];

  const fromReplyToCheck = checkFromReplyToMismatch(emlData);
  if (fromReplyToCheck) signals.push(fromReplyToCheck);

  const messageIdCheck = checkMessageIdDomain(emlData);
  if (messageIdCheck) signals.push(messageIdCheck);

  const dateCheck = checkDateReceivedDeviation(emlData);
  if (dateCheck) signals.push(dateCheck);

  const authCheck = checkMissingAuthentication(emlData);
  if (authCheck) signals.push(...authCheck);

  const subjectCheck = checkSuspiciousSubject(emlData);
  if (subjectCheck) signals.push(subjectCheck);

  const urgentCheck = checkUrgentLanguage(emlData);
  if (urgentCheck) signals.push(urgentCheck);

  return signals;
}

function checkFromReplyToMismatch(emlData) {
  const h = emlData.headers;
  if (!h.from || !h.from.email) return null;
  if (!h.replyTo || h.replyTo.length === 0) return null;

  const fromDomain = h.from.email.split('@')[1]?.toLowerCase();
  const replyToDomain = h.replyTo[0].email?.split('@')[1]?.toLowerCase();

  if (!fromDomain || !replyToDomain) return null;

  if (fromDomain !== replyToDomain) {
    return {
      type: 'from_replyto_domain_mismatch',
      risk: 'medium',
      category: 'header_spoofing',
      description: `发件人域名 (${fromDomain}) 与回复地址域名 (${replyToDomain}) 不一致，可能是仿冒邮件`,
      details: {
        fromEmail: h.from.email,
        fromDomain,
        replyToEmail: h.replyTo[0].email,
        replyToDomain
      }
    };
  }

  return null;
}

function checkMessageIdDomain(emlData) {
  const h = emlData.headers;
  if (!h.messageId || !h.from || !h.from.email) return null;

  const msgIdDomain = extractMessageIdDomain(h.messageId)?.toLowerCase();
  const fromDomain = h.from.email.split('@')[1]?.toLowerCase();

  if (!msgIdDomain || !fromDomain) return null;

  const isIpDomain = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(msgIdDomain);
  const domainMismatch = msgIdDomain !== fromDomain && !msgIdDomain.endsWith('.' + fromDomain) && !fromDomain.endsWith('.' + msgIdDomain);

  if (isIpDomain) {
    return {
      type: 'messageid_ip_domain',
      risk: 'low',
      category: 'header_anomaly',
      description: `Message-ID 使用 IP 地址域名 (${msgIdDomain})，较为可疑`,
      details: {
        messageId: h.messageId,
        msgIdDomain
      }
    };
  }

  if (domainMismatch) {
    return {
      type: 'messageid_domain_mismatch',
      risk: 'low',
      category: 'header_anomaly',
      description: `Message-ID 域名 (${msgIdDomain}) 与发件人域名 (${fromDomain}) 不匹配`,
      details: {
        messageId: h.messageId,
        msgIdDomain,
        fromDomain
      }
    };
  }

  return null;
}

function checkDateReceivedDeviation(emlData) {
  const h = emlData.headers;
  if (!h.date) return null;

  const allHeaders = h.allHeaders || {};
  const receivedHeaders = allHeaders['received'] || [];

  if (receivedHeaders.length === 0) return null;

  let latestReceivedDate = null;
  for (const rh of receivedHeaders) {
    const dateMatch = rh.match(/;\s*([^;]+)\s*$/);
    if (dateMatch) {
      const d = new Date(dateMatch[1].trim());
      if (!isNaN(d.getTime())) {
        if (!latestReceivedDate || d > latestReceivedDate) {
          latestReceivedDate = d;
        }
      }
    }
  }

  if (!latestReceivedDate) return null;

  const dateHeader = h.date;
  const diffMs = Math.abs(dateHeader.getTime() - latestReceivedDate.getTime());
  const diffHours = diffMs / (1000 * 60 * 60);

  if (diffHours > 24) {
    return {
      type: 'date_received_deviation_large',
      risk: 'high',
      category: 'timestamp_anomaly',
      description: `Date 头与最新 Received 时间偏差超过 24 小时 (约 ${Math.round(diffHours)} 小时)，可能是伪造的时间戳`,
      details: {
        dateHeader: dateHeader.toISOString(),
        latestReceived: latestReceivedDate.toISOString(),
        deviationHours: Math.round(diffHours * 10) / 10
      }
    };
  }

  if (diffHours > 2) {
    return {
      type: 'date_received_deviation',
      risk: 'low',
      category: 'timestamp_anomaly',
      description: `Date 头与最新 Received 时间偏差较大 (约 ${Math.round(diffHours)} 小时)`,
      details: {
        dateHeader: dateHeader.toISOString(),
        latestReceived: latestReceivedDate.toISOString(),
        deviationHours: Math.round(diffHours * 10) / 10
      }
    };
  }

  return null;
}

function checkMissingAuthentication(emlData) {
  const issues = [];
  const allHeaders = emlData.headers.allHeaders || {};

  const hasDkim = allHeaders['dkim-signature'] && allHeaders['dkim-signature'].length > 0;
  const hasSpf = allHeaders['received-spf'] && allHeaders['received-spf'].length > 0;
  const hasDmarc = allHeaders['authentication-results'] && allHeaders['authentication-results'].some(
    h => h.toLowerCase().includes('dmarc')
  );

  if (!hasDkim) {
    issues.push({
      type: 'missing_dkim',
      risk: 'low',
      category: 'authentication',
      description: '邮件缺少 DKIM 签名，无法验证发件人身份',
      details: { authentication: 'DKIM' }
    });
  }

  if (!hasSpf) {
    issues.push({
      type: 'missing_spf',
      risk: 'low',
      category: 'authentication',
      description: '邮件缺少 SPF 认证结果，无法验证发件人 IP 合法性',
      details: { authentication: 'SPF' }
    });
  }

  if (!hasDmarc) {
    issues.push({
      type: 'missing_dmarc',
      risk: 'low',
      category: 'authentication',
      description: '邮件缺少 DMARC 认证结果，策略执行情况未知',
      details: { authentication: 'DMARC' }
    });
  }

  return issues;
}

function checkSuspiciousSubject(emlData) {
  const subject = emlData.headers.subject || '';
  if (!subject) return null;

  const suspiciousPatterns = [
    { pattern: /账户|账号|登录|密码|验证|security|verify|password|account/i, weight: 1 },
    { pattern: /紧急|立即|马上|立刻|urgent|immediately|action required/i, weight: 1 },
    { pattern: /银行|支付|转账|付款|发票|invoice|payment|bank/i, weight: 1 },
    { pattern: /中奖|获奖|奖金|礼品|免费|free|gift|win|won/i, weight: 1 },
    { pattern: /包裹|快递|物流|delivery|package|tracking/i, weight: 1 }
  ];

  let score = 0;
  const matched = [];
  for (const p of suspiciousPatterns) {
    if (p.pattern.test(subject)) {
      score += p.weight;
      matched.push(p.pattern.source);
    }
  }

  if (score >= 2) {
    return {
      type: 'suspicious_subject',
      risk: score >= 3 ? 'medium' : 'low',
      category: 'content_suspicion',
      description: `邮件主题包含多个可疑关键词 (${score} 个)，可能是钓鱼或诈骗邮件`,
      details: {
        subject,
        matchedPatterns: matched,
        score
      }
    };
  }

  return null;
}

function checkUrgentLanguage(emlData) {
  const bodies = emlData.bodies;
  const text = bodies.text || bodies.htmlAsText || '';
  if (!text) return null;

  const urgentPatterns = [
    /立即行动|立即处理|紧急通知|紧急处理|速办|加急/i,
    /账户异常|账户被盗|安全警告|安全提醒|密码泄露/i,
    /限时|过期|失效|即将到期|最后通牒/i,
    /点击|链接|验证|确认|更新资料/i,
    /act now|urgent|immediately|action required|verify your/i,
    /account suspended|security alert|password expire/i
  ];

  let count = 0;
  const matched = [];
  const textLower = text.toLowerCase();

  for (const p of urgentPatterns) {
    const matches = textLower.match(new RegExp(p.source, 'gi'));
    if (matches) {
      count += matches.length;
      matched.push(p.source);
    }
  }

  if (count >= 3) {
    return {
      type: 'urgent_language',
      risk: count >= 5 ? 'medium' : 'low',
      category: 'content_suspicion',
      description: `正文中包含多处紧急/威胁性语言 (${count} 处)，常见于钓鱼邮件`,
      details: {
        count,
        matchedPatterns: matched
      }
    };
  }

  return null;
}

function analyzeAuthenticationResults(emlData) {
  const allHeaders = emlData.headers.allHeaders || {};
  const results = {
    dkim: null,
    spf: null,
    dmarc: null,
    raw: []
  };

  const dkimHeaders = allHeaders['dkim-signature'] || [];
  if (dkimHeaders.length > 0) {
    results.dkim = {
      present: true,
      count: dkimHeaders.length,
      signatures: dkimHeaders.map(dkim => parseDkimSignature(dkim))
    };
  } else {
    results.dkim = { present: false, count: 0, signatures: [] };
  }

  const spfHeaders = allHeaders['received-spf'] || [];
  if (spfHeaders.length > 0) {
    results.spf = spfHeaders.map(spf => parseSpfResult(spf));
  } else {
    results.spf = [];
  }

  const authResults = allHeaders['authentication-results'] || [];
  if (authResults.length > 0) {
    results.raw = authResults;
    for (const ar of authResults) {
      const dmarcMatch = ar.match(/dmarc=(\w+)/i);
      if (dmarcMatch) {
        results.dmarc = {
          result: dmarcMatch[1].toLowerCase(),
          raw: ar
        };
      }
    }
  }

  return results;
}

function parseDkimSignature(dkimHeader) {
  const result = {};
  const params = dkimHeader.split(';');
  for (const param of params) {
    const trimmed = param.trim();
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex !== -1) {
      const key = trimmed.substring(0, eqIndex).trim().toLowerCase();
      const value = trimmed.substring(eqIndex + 1).trim();
      result[key] = value;
    }
  }
  return {
    domain: result.d || '',
    selector: result.s || '',
    algorithm: result.a || '',
    bodyHash: result.bh || '',
    signature: result.b ? result.b.substring(0, 32) + '...' : ''
  };
}

function parseSpfResult(spfHeader) {
  const result = {};
  const match = spfHeader.match(/^(\w+)/);
  if (match) {
    result.result = match[1].toLowerCase();
  }
  const ipMatch = spfHeader.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  if (ipMatch) {
    result.ip = ipMatch[1];
  }
  result.raw = spfHeader;
  return result;
}

function extractAndAnalyzeUrls(emlData) {
  const urls = {
    all: [],
    externalImages: [],
    suspiciousShortLinks: [],
    ipDirectLinks: [],
    attachmentLinks: [],
    count: 0
  };

  const bodies = emlData.bodies;

  if (bodies.text) {
    const textUrls = extractUrlsFromText(bodies.text);
    urls.all.push(...textUrls.map(u => ({ ...u, source: 'text_body' })));
  }

  if (bodies.html) {
    const htmlUrls = extractUrlsFromHtml(bodies.html);
    urls.all.push(...htmlUrls.map(u => ({ ...u, source: 'html_body' })));
    urls.externalImages = extractExternalImageUrls(bodies.html).map(u => ({
      url: u,
      domain: getDomainFromUrl(u),
      source: 'html_image'
    }));
  }

  if (bodies.htmlAsText) {
    const textUrls = extractUrlsFromText(bodies.htmlAsText);
    for (const u of textUrls) {
      if (!urls.all.some(existing => existing.url === u.url)) {
        urls.all.push({ ...u, source: 'html_text' });
      }
    }
  }

  const attachments = findAllAttachments(emlData.mimeTree);
  for (const att of attachments) {
    if (att.body) {
      const decoded = decodeContent(att.body, att.contentTransferEncoding, att.charset);
      if (decoded.text) {
        const attUrls = extractUrlsFromText(decoded.text);
        for (const u of attUrls) {
          const attUrl = { ...u, source: 'attachment', attachment: att.filename || 'unnamed' };
          urls.attachmentLinks.push(attUrl);
          if (!urls.all.some(existing => existing.url === u.url)) {
            urls.all.push(attUrl);
          }
        }
      }
    }
  }

  const uniqueUrls = [];
  const seen = new Set();
  for (const u of urls.all) {
    if (!seen.has(u.url)) {
      seen.add(u.url);
      uniqueUrls.push(u);
    }
  }
  urls.all = uniqueUrls;
  urls.count = uniqueUrls.length;

  for (const u of urls.all) {
    const domain = u.domain || '';
    const domainLower = domain.toLowerCase();

    if (SHORT_URL_DOMAINS.some(sd => domainLower === sd || domainLower.endsWith('.' + sd))) {
      urls.suspiciousShortLinks.push({
        ...u,
        reason: '疑似短链接服务域名'
      });
    }

    if (isIpAddressUrl(u.url)) {
      urls.ipDirectLinks.push({
        ...u,
        reason: '使用 IP 地址直连，未使用域名'
      });
    }
  }

  return urls;
}

function extractUrlsFromText(text) {
  const urls = [];
  const urlRegex = /https?:\/\/[^\s<>\[\]"']+/gi;
  let match;

  while ((match = urlRegex.exec(text)) !== null) {
    let url = match[0];
    url = url.replace(/[.,;:!?)\]]+$/, '');
    urls.push({
      url,
      domain: getDomainFromUrl(url)
    });
  }

  return urls;
}

function extractUrlsFromHtml(html) {
  const urls = [];
  const hrefRegex = /<a[^>]+href=["']([^"']+)["'][^>]*>/gi;
  let match;

  while ((match = hrefRegex.exec(html)) !== null) {
    const url = match[1];
    if (url.startsWith('http://') || url.startsWith('https://')) {
      urls.push({
        url,
        domain: getDomainFromUrl(url)
      });
    }
  }

  return urls;
}

function getDomainFromUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname;
  } catch (e) {
    return '';
  }
}

function isIpAddressUrl(url) {
  const domain = getDomainFromUrl(url);
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain);
}

function auditAttachments(emlData) {
  const attachments = emlData.attachments || [];
  const results = [];

  for (const att of attachments) {
    const ext = att.extension ? att.extension.toLowerCase() : '';
    const analysis = {
      filename: att.filename,
      contentType: att.contentType,
      size: att.size,
      sizeFormatted: att.sizeFormatted,
      sha256: att.sha256,
      extension: ext,
      contentId: att.contentId || null,
      contentDisposition: att.contentDisposition || null,
      isInline: att.isInline,
      suspicious: false,
      flags: []
    };

    const suspiciousExts = ['.exe', '.com', '.bat', '.cmd', '.pif', '.scr', '.vbs', '.js',
      '.wsf', '.wsh', '.ps1', '.hta', '.jar', '.apk', '.iso'];
    if (suspiciousExts.includes(ext)) {
      analysis.suspicious = true;
      analysis.flags.push({ type: 'suspicious_extension', message: `可疑的可执行文件扩展名 ${ext}` });
    }

    const macroExts = ['.docm', '.dotm', '.xlsm', '.xltm', '.pptm', '.potm', '.ppam'];
    if (macroExts.includes(ext)) {
      analysis.suspicious = true;
      analysis.flags.push({ type: 'macro_enabled', message: '启用宏的 Office 文档' });
    }

    const parts = (att.filename || '').split('.');
    if (parts.length >= 3) {
      const lastExt = '.' + parts[parts.length - 1].toLowerCase();
      const secondLastExt = '.' + parts[parts.length - 2].toLowerCase();
      const docExts = ['.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.jpg', '.png', '.gif'];
      if (docExts.includes(secondLastExt) && (suspiciousExts.includes(lastExt) || macroExts.includes(lastExt))) {
        analysis.suspicious = true;
        analysis.flags.push({ type: 'double_extension', message: `疑似双扩展名伪装 (${secondLastExt}${lastExt})` });
      }
    }

    results.push(analysis);
  }

  return {
    count: results.length,
    attachments: results,
    suspiciousCount: results.filter(a => a.suspicious).length
  };
}

function generateForensicJsonReport(audit) {
  return JSON.stringify(audit, null, 2);
}

function generateForensicMarkdownReport(audit) {
  let md = '';

  md += '# 邮件取证审计报告\n\n';
  md += `> 生成时间: ${new Date().toLocaleString('zh-CN')}\n`;
  if (audit.file) {
    md += `> 文件: ${audit.file}\n`;
  }
  md += `> 总体风险等级: ${getRiskBadge(audit.overallRisk)}\n`;
  md += `> 可疑信号: ${audit.signalSummary.total} 个 `;
  md += `(严重:${audit.signalSummary.critical} `;
  md += `高:${audit.signalSummary.high} `;
  md += `中:${audit.signalSummary.medium} `;
  md += `低:${audit.signalSummary.low})\n`;
  md += '\n---\n\n';

  md += '## 一、邮件头信息审计\n\n';

  const h = audit.headers;
  md += '### 1.1 收发件信息\n\n';
  md += '| 字段 | 内容 |\n';
  md += '|------|------|\n';
  md += `| **发件人 (From)** | ${h.from ? formatAddress(h.from) : '(无)'} |\n`;
  md += `| **发件人域名** | ${h.fromDomain || '(无)'} |\n`;
  md += `| **收件人 (To)** | ${h.to.length > 0 ? h.to.map(a => formatAddress(a)).join(', ') : '(无)'} |\n`;
  md += `| **抄送 (Cc)** | ${h.cc.length > 0 ? h.cc.map(a => formatAddress(a)).join(', ') : '(无)'} |\n`;
  md += `| **密送 (Bcc)** | ${h.bcc.length > 0 ? h.bcc.map(a => formatAddress(a)).join(', ') : '(无)'} |\n`;
  md += `| **回复地址 (Reply-To)** | ${h.replyTo.length > 0 ? h.replyTo.map(a => formatAddress(a)).join(', ') : '(无)'} |\n`;
  md += `| **回复地址域名** | ${h.replyToDomain || '(无)'} |\n`;
  md += '\n';

  md += '### 1.2 其他头信息\n\n';
  md += `- **主题 (Subject):** ${h.subject || '(无主题)'}\n`;
  md += `- **日期 (Date):** ${h.dateString || '(无)'}\n`;
  md += `- **Message-ID:** ${h.messageId || '(无)'}\n`;
  md += `- **Message-ID 域名:** ${h.messageIdDomain || '(无)'}\n`;
  md += `- **MIME 版本:** ${h.mimeVersion || '(无)'}\n`;
  md += '\n---\n\n';

  md += '## 二、Received 链路分析\n\n';
  md += `共 **${audit.receivedChain.count}** 跳\n\n`;

  if (audit.receivedChain.hops.length > 0) {
    md += '### 链路详情（按时间倒序）\n\n';
    audit.receivedChain.hops.forEach((hop, i) => {
      md += `#### 第 ${i + 1} 跳\n\n`;
      md += `- **From:** ${hop.from || '(未知)'}\n`;
      if (hop.fromIp) md += `  - **IP:** ${hop.fromIp}\n`;
      md += `- **By:** ${hop.by || '(未知)'}\n`;
      if (hop.with) md += `- **协议:** ${hop.with}\n`;
      if (hop.id) md += `- **ID:** ${hop.id}\n`;
      if (hop.for) md += `- **收件人:** ${hop.for}\n`;
      md += `- **时间:** ${hop.dateString || '(未知)'}\n`;
      if (hop.delayFormatted !== undefined && hop.delayFormatted !== null) {
        md += `- **相对前一跳延迟:** ${hop.delayFormatted}\n`;
      }
      md += '\n';
    });
  } else {
    md += '*未找到 Received 头*\n\n';
  }

  md += '---\n\n';

  md += '## 三、认证结果分析\n\n';

  const auth = audit.authenticationResults;

  md += '### 3.1 DKIM\n\n';
  if (auth.dkim && auth.dkim.present) {
    md += `- **状态:** ✅ 存在 (${auth.dkim.count} 个签名)\n`;
    for (let i = 0; i < auth.dkim.signatures.length; i++) {
      const sig = auth.dkim.signatures[i];
      md += `  - 签名 ${i + 1}: 域=${sig.domain}, 选择器=${sig.selector}, 算法=${sig.algorithm}\n`;
    }
  } else {
    md += '- **状态:** ❌ 缺失\n';
  }
  md += '\n';

  md += '### 3.2 SPF\n\n';
  if (auth.spf && auth.spf.length > 0) {
    for (const spf of auth.spf) {
      md += `- **结果:** ${spf.result || '(未知)'}\n`;
      if (spf.ip) md += `  - **IP:** ${spf.ip}\n`;
    }
  } else {
    md += '- **状态:** ❌ 缺失\n';
  }
  md += '\n';

  md += '### 3.3 DMARC\n\n';
  if (auth.dmarc) {
    md += `- **结果:** ${auth.dmarc.result}\n`;
  } else {
    md += '- **状态:** ❌ 缺失/未检测到\n';
  }
  md += '\n';

  md += '---\n\n';

  md += '## 四、可疑信号检测\n\n';

  const signals = audit.suspiciousSignals;
  if (signals.length === 0) {
    md += '*未检测到可疑信号*\n\n';
  } else {
    md += `共检测到 **${signals.length}** 个可疑信号:\n\n`;

    const sortedSignals = [...signals].sort((a, b) => compareRisk(b.risk, a.risk));

    for (let i = 0; i < sortedSignals.length; i++) {
      const signal = sortedSignals[i];
      const badge = getRiskBadge(signal.risk);
      md += `### ${i + 1}. ${badge} - ${signal.description}\n\n`;
      md += `- **类型:** ${signal.type}\n`;
      md += `- **分类:** ${signal.category || '其他'}\n`;

      if (signal.details) {
        md += '\n**详情:**\n\n';
        for (const [key, value] of Object.entries(signal.details)) {
          if (Array.isArray(value)) {
            md += `- ${key}:\n`;
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

  md += '---\n\n';

  md += '## 五、URL 与链接分析\n\n';

  const urls = audit.urls;
  md += `- **总链接数:** ${urls.count}\n`;
  md += `- **外部图片:** ${urls.externalImages.length} 个\n`;
  md += `- **可疑短链:** ${urls.suspiciousShortLinks.length} 个\n`;
  md += `- **IP 直连:** ${urls.ipDirectLinks.length} 个\n`;
  md += `- **附件内嵌链接:** ${urls.attachmentLinks.length} 个\n`;
  md += '\n';

  if (urls.all.length > 0) {
    md += '### 5.1 所有链接\n\n';
    md += '| # | URL | 域名 | 来源 |\n';
    md += '|---|-----|------|------|\n';
    urls.all.forEach((u, i) => {
      md += `| ${i + 1} | ${truncateUrl(u.url, 50)} | ${u.domain || '-'} | ${u.source} |\n`;
    });
    md += '\n';
  }

  if (urls.externalImages.length > 0) {
    md += '### 5.2 外部图片链接\n\n';
    urls.externalImages.forEach((u, i) => {
      md += `${i + 1}. ${u.url}\n`;
    });
    md += '\n';
  }

  if (urls.suspiciousShortLinks.length > 0) {
    md += '### 5.3 ⚠️ 可疑短链接\n\n';
    urls.suspiciousShortLinks.forEach((u, i) => {
      md += `${i + 1}. ${u.url} - ${u.reason}\n`;
    });
    md += '\n';
  }

  if (urls.ipDirectLinks.length > 0) {
    md += '### 5.4 ⚠️ IP 直连链接\n\n';
    urls.ipDirectLinks.forEach((u, i) => {
      md += `${i + 1}. ${u.url} - ${u.reason}\n`;
    });
    md += '\n';
  }

  if (urls.attachmentLinks.length > 0) {
    md += '### 5.5 附件内嵌链接\n\n';
    urls.attachmentLinks.forEach((u, i) => {
      md += `${i + 1}. ${u.url} (附件: ${u.attachment})\n`;
    });
    md += '\n';
  }

  md += '---\n\n';

  md += '## 六、附件审计\n\n';

  const attAudit = audit.attachmentsAudit;
  md += `- **附件总数:** ${attAudit.count}\n`;
  md += `- **可疑附件:** ${attAudit.suspiciousCount} 个\n`;
  md += '\n';

  if (attAudit.attachments.length > 0) {
    md += '### 附件详情\n\n';
    attAudit.attachments.forEach((att, i) => {
      const statusEmoji = att.suspicious ? '⚠️' : '✅';
      md += `#### ${i + 1}. ${statusEmoji} ${att.filename}\n\n`;
      md += `- **类型:** ${att.contentType}\n`;
      md += `- **大小:** ${att.sizeFormatted}\n`;
      md += `- **扩展名:** ${att.extension || '(无)'}\n`;
      md += `- **Content-ID:** ${att.contentId || '(无)'}\n`;
      md += `- **SHA256:** \`${att.sha256.substring(0, 32)}...\`\n`;
      md += `- **内联:** ${att.isInline ? '是' : '否'}\n`;

      if (att.flags.length > 0) {
        md += '\n**风险标记:**\n\n';
        att.flags.forEach(f => md += `- ${f.message}\n`);
      }
      md += '\n';
    });
  } else {
    md += '*无附件*\n\n';
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

function compareRisk(r1, r2) {
  const order = ['safe', 'low', 'medium', 'high', 'critical'];
  return order.indexOf(r1) - order.indexOf(r2);
}

function truncateUrl(url, maxLen) {
  if (url.length <= maxLen) return url;
  return url.substring(0, maxLen - 3) + '...';
}

function exportForensicReport(audit, outputPath) {
  const fs = require('fs');
  const path = require('path');

  const ext = path.extname(outputPath).toLowerCase();
  let content;

  if (ext === '.md' || ext === '.markdown') {
    content = generateForensicMarkdownReport(audit);
  } else {
    content = generateForensicJsonReport(audit);
  }

  fs.writeFileSync(outputPath, content, 'utf8');
  return { path: outputPath, format: ext === '.md' || ext === '.markdown' ? 'markdown' : 'json' };
}

module.exports = {
  runForensicAudit,
  generateForensicJsonReport,
  generateForensicMarkdownReport,
  exportForensicReport,
  analyzeReceivedChain,
  detectSuspiciousSignals,
  extractAndAnalyzeUrls,
  analyzeAuthenticationResults
};
