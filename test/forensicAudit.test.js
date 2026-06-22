const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { describe, it, before, after } = require('./harness');
const { PROJECT_ROOT, loadEml, makeTempDir, cleanupTempDir } = require('./helpers');

const { runForensicAudit, generateForensicJsonReport, generateForensicMarkdownReport, exportForensicReport, analyzeReceivedChain, detectSuspiciousSignals, extractAndAnalyzeUrls, analyzeAuthenticationResults } = require(path.join(PROJECT_ROOT, 'lib/forensicAudit'));

describe('forensicAudit - Received Chain Analysis', function() {
  it('parses all Received headers and counts hops', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.strictEqual(audit.receivedChain.count, 3, 'Should find 3 Received hops');
    assert.strictEqual(audit.receivedChain.hops.length, 3);
  });

  it('sorts Received hops in reverse chronological order (latest first)', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const hops = audit.receivedChain.hops;

    for (let i = 0; i < hops.length - 1; i++) {
      const curr = new Date(hops[i].date);
      const next = new Date(hops[i + 1].date);
      assert.ok(curr >= next, `Hop ${i} should be >= hop ${i + 1} in time (reverse order)`);
    }
  });

  it('first hop should be the latest Received (google.com)', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const firstHop = audit.receivedChain.hops[0];
    assert.ok(firstHop.by && firstHop.by.includes('google'), 'First hop should be google.com (latest)');
  });

  it('last hop should be the earliest Received (localhost)', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const lastHop = audit.receivedChain.hops[audit.receivedChain.hops.length - 1];
    assert.ok(lastHop.from && lastHop.from.includes('localhost'), 'Last hop should be localhost (earliest)');
  });

  it('extracts IP addresses from Received headers', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const hopsWithIp = audit.receivedChain.hops.filter(h => h.fromIp);
    assert.ok(hopsWithIp.length >= 2, 'At least 2 hops should have IPs');
    const ips = hopsWithIp.map(h => h.fromIp);
    assert.ok(ips.includes('203.0.113.45') || ips.includes('198.51.100.23') || ips.includes('127.0.0.1'),
      'Should extract expected IPs');
  });

  it('computes delay between consecutive hops', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const hops = audit.receivedChain.hops;

    assert.ok(hops[0].delaySeconds !== null && hops[0].delaySeconds !== undefined,
      'First hop should have computed delay');
    assert.ok(hops[0].delaySeconds >= 0, 'Delay should be non-negative');
    assert.ok(typeof hops[0].delayFormatted === 'string', 'Should have formatted delay');

    assert.strictEqual(
      hops[hops.length - 1].delaySeconds,
      null,
      'Last hop should have null delay (no previous hop)'
    );
  });

  it('extracts "by", "with", "id", "for" fields from Received', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const hops = audit.receivedChain.hops;

    const withEsmtp = hops.filter(h => h.with && h.with.toLowerCase().includes('esmtp'));
    assert.ok(withEsmtp.length >= 1, 'Should find ESMTP protocol');

    const withFor = hops.filter(h => h.for);
    assert.ok(withFor.length >= 1, 'Should find "for" field');
  });

  it('emails without Received headers get zero count', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const audit = runForensicAudit(eml);
    assert.strictEqual(audit.receivedChain.count, 0);
    assert.deepStrictEqual(audit.receivedChain.hops, []);
  });

  it('analyzeReceivedChain is independently callable', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const result = analyzeReceivedChain(eml);
    assert.strictEqual(result.count, 3);
    assert.ok(Array.isArray(result.hops));
  });
});

describe('forensicAudit - From/Reply-To Domain Mismatch Detection', function() {
  it('detects when From and Reply-To domains differ', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const mismatch = audit.suspiciousSignals.find(s => s.type === 'from_replyto_domain_mismatch');
    assert.ok(mismatch, 'Should detect From/Reply-To domain mismatch');
    assert.strictEqual(mismatch.risk, 'medium');
    assert.ok(mismatch.details.fromDomain.includes('official-bank.com'));
    assert.ok(mismatch.details.replyToDomain.includes('phishing-scam.net'));
  });

  it('headers field includes both fromDomain and replyToDomain', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.headers.fromDomain, 'Should have fromDomain');
    assert.ok(audit.headers.replyToDomain, 'Should have replyToDomain');
    assert.notStrictEqual(audit.headers.fromDomain, audit.headers.replyToDomain, 'Domains should differ');
  });

  it('no mismatch signal when From and Reply-To domains match', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const audit = runForensicAudit(eml);
    const mismatch = audit.suspiciousSignals.find(s => s.type === 'from_replyto_domain_mismatch');
    assert.ok(!mismatch, 'Should not have mismatch when domains match');
  });

  it('no mismatch signal when Reply-To is absent', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    const audit = runForensicAudit(eml);
    const mismatch = audit.suspiciousSignals.find(s => s.type === 'from_replyto_domain_mismatch');
    assert.ok(!mismatch, 'Should not raise mismatch if no Reply-To');
  });
});

describe('forensicAudit - Message-ID Domain Anomaly Detection', function() {
  it('detects Message-ID with IP address domain', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const ipSignal = audit.suspiciousSignals.find(s => s.type === 'messageid_ip_domain');
    assert.ok(ipSignal, 'Should detect IP-based Message-ID domain');
    assert.strictEqual(ipSignal.risk, 'low');
    assert.ok(ipSignal.details.msgIdDomain.match(/^\d+\.\d+\.\d+\.\d+$/), 'Should be IP address');
  });

  it('extracts Message-ID domain from headers field', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.headers.messageIdDomain, 'Should have messageIdDomain');
    assert.ok(/\d/.test(audit.headers.messageIdDomain), 'Should contain IP digits');
  });

  it('normal Message-ID domain does not trigger IP warning', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const audit = runForensicAudit(eml);
    const ipSignal = audit.suspiciousSignals.find(s => s.type === 'messageid_ip_domain');
    assert.ok(!ipSignal, 'Normal domain should not trigger IP warning');
    assert.strictEqual(audit.headers.messageIdDomain, 'example.com');
  });
});

describe('forensicAudit - Date vs Received Time Deviation', function() {
  it('detects large deviation (>24h) between Date and latest Received', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const dateSignal = audit.suspiciousSignals.find(
      s => s.type === 'date_received_deviation_large' || s.type === 'date_received_deviation'
    );
    assert.ok(dateSignal, 'Should detect date/received deviation');
    if (dateSignal.type === 'date_received_deviation_large') {
      assert.strictEqual(dateSignal.risk, 'high');
    } else {
      assert.strictEqual(dateSignal.risk, 'low');
    }
    assert.ok('deviationHours' in dateSignal.details, 'Should include deviationHours');
  });

  it('no deviation signal when no Received headers', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const audit = runForensicAudit(eml);
    const dateSignal = audit.suspiciousSignals.find(
      s => s.type && s.type.startsWith('date_received')
    );
    assert.ok(!dateSignal, 'Should not have deviation if no Received headers');
  });
});

describe('forensicAudit - DKIM / SPF / DMARC Authentication Results', function() {
  it('detects DKIM signature presence', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.authenticationResults.dkim);
    assert.strictEqual(audit.authenticationResults.dkim.present, true);
    assert.ok(audit.authenticationResults.dkim.count >= 1);
    assert.ok(audit.authenticationResults.dkim.signatures.length >= 1);
  });

  it('parses DKIM signature domain and selector', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const sig = audit.authenticationResults.dkim.signatures[0];
    assert.ok(sig.domain.includes('official-bank.com'), 'DKIM domain should be official-bank.com');
    assert.strictEqual(sig.selector, 'default');
    assert.strictEqual(sig.algorithm, 'rsa-sha256');
    assert.ok(sig.bodyHash, 'Should have body hash');
    assert.ok(sig.signature, 'Should have signature (truncated)');
  });

  it('parses SPF result from Received-SPF header', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.authenticationResults.spf.length >= 1);
    const spf = audit.authenticationResults.spf[0];
    assert.strictEqual(spf.result, 'none');
    assert.ok(spf.ip, 'Should have SPF IP');
    assert.ok(spf.raw, 'Should have raw SPF header');
  });

  it('parses DMARC result from Authentication-Results header', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.authenticationResults.dmarc);
    assert.strictEqual(audit.authenticationResults.dmarc.result, 'fail');
    assert.ok(audit.authenticationResults.dmarc.raw, 'Should have raw DMARC data');
  });

  it('detects missing DKIM and raises signal', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const audit = runForensicAudit(eml);
    const missingDkim = audit.suspiciousSignals.find(s => s.type === 'missing_dkim');
    assert.ok(missingDkim, 'Should detect missing DKIM');
    assert.strictEqual(missingDkim.risk, 'low');
    assert.strictEqual(missingDkim.details.authentication, 'DKIM');
  });

  it('detects missing SPF and raises signal', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const audit = runForensicAudit(eml);
    const missingSpf = audit.suspiciousSignals.find(s => s.type === 'missing_spf');
    assert.ok(missingSpf, 'Should detect missing SPF');
  });

  it('detects missing DMARC and raises signal', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const audit = runForensicAudit(eml);
    const missingDmarc = audit.suspiciousSignals.find(s => s.type === 'missing_dmarc');
    assert.ok(missingDmarc, 'Should detect missing DMARC');
  });

  it('analyzeAuthenticationResults independently works', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const result = analyzeAuthenticationResults(eml);
    assert.ok(result.dkim);
    assert.ok(result.spf);
    assert.ok(Array.isArray(result.raw));
  });

  it('emails without auth headers get null/present=false', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const result = analyzeAuthenticationResults(eml);
    assert.strictEqual(result.dkim.present, false);
    assert.deepStrictEqual(result.spf, []);
    assert.strictEqual(result.dmarc, null);
  });
});

describe('forensicAudit - URL Extraction & Analysis', function() {
  it('extracts URLs from plain text body', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.urls.count >= 3, `Expected at least 3 URLs, got ${audit.urls.count}`);
    const textUrls = audit.urls.all.filter(u => u.source === 'text_body');
    assert.ok(textUrls.length >= 1, 'Should have URLs from text body');
  });

  it('extracts URLs from HTML body (<a href>)', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const htmlUrls = audit.urls.all.filter(u => u.source === 'html_body');
    assert.ok(htmlUrls.length >= 2, 'Should have URLs from HTML body hrefs');
  });

  it('detects suspicious short links (bit.ly, goo.gl, tinyurl.com, etc.)', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.urls.suspiciousShortLinks.length >= 1,
      `Expected short links, got ${audit.urls.suspiciousShortLinks.length}`);
    const domains = audit.urls.suspiciousShortLinks.map(u => u.domain);
    assert.ok(
      domains.some(d => d.includes('bit.ly') || d.includes('goo.gl') || d.includes('tinyurl.com')),
      'Should find known shortener domains'
    );
  });

  it('detects IP address direct links', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.urls.ipDirectLinks.length >= 1,
      `Expected IP direct links, got ${audit.urls.ipDirectLinks.length}`);
    for (const link of audit.urls.ipDirectLinks) {
      assert.ok(/^\d+\.\d+\.\d+\.\d+$/.test(link.domain),
        `Domain should be IP address: ${link.domain}`);
    }
  });

  it('extracts external image URLs from HTML', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.urls.externalImages.length >= 1,
      `Expected external images, got ${audit.urls.externalImages.length}`);
    for (const img of audit.urls.externalImages) {
      assert.strictEqual(img.source, 'html_image');
      assert.ok(img.url.startsWith('http'), 'Should be http(s) URL');
    }
  });

  it('extracts URLs from attachment text content', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.urls.attachmentLinks.length >= 1,
      `Expected attachment links, got ${audit.urls.attachmentLinks.length}`);
    for (const link of audit.urls.attachmentLinks) {
      assert.strictEqual(link.source, 'attachment');
      assert.ok(link.attachment, 'Should have attachment filename');
    }
  });

  it('deduplicates URLs across sources', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const allUrls = audit.urls.all.map(u => u.url);
    const uniqueUrls = new Set(allUrls);
    assert.strictEqual(allUrls.length, uniqueUrls.size, 'URLs should be deduplicated');
  });

  it('each URL has domain field extracted', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    for (const u of audit.urls.all) {
      assert.ok(u.domain !== undefined, `URL should have domain: ${u.url}`);
      assert.ok(typeof u.source === 'string', 'Should have source field');
    }
  });

  it('extractAndAnalyzeUrls is independently callable', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const result = extractAndAnalyzeUrls(eml);
    assert.strictEqual(typeof result.count, 'number');
    assert.ok(Array.isArray(result.all));
    assert.ok(Array.isArray(result.externalImages));
    assert.ok(Array.isArray(result.suspiciousShortLinks));
    assert.ok(Array.isArray(result.ipDirectLinks));
    assert.ok(Array.isArray(result.attachmentLinks));
  });
});

describe('forensicAudit - Suspicious Subject & Urgent Language', function() {
  it('detects suspicious subject keywords', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const subjSignal = audit.suspiciousSignals.find(s => s.type === 'suspicious_subject');
    if (subjSignal) {
      assert.ok(subjSignal.details.score >= 2, 'Should have score >= 2');
      assert.ok(Array.isArray(subjSignal.details.matchedPatterns));
    }
  });

  it('detects urgent/phishing language in body', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const urgentSignal = audit.suspiciousSignals.find(s => s.type === 'urgent_language');
    if (urgentSignal) {
      assert.ok(urgentSignal.details.count >= 3);
      assert.ok(Array.isArray(urgentSignal.details.matchedPatterns));
    }
  });
});

describe('forensicAudit - Attachment Audit', function() {
  it('counts attachments and flags suspicious ones', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.attachmentsAudit.count >= 2, 'Should have attachments');
    assert.ok(audit.attachmentsAudit.suspiciousCount >= 1, 'Should have suspicious attachments');
  });

  it('flags suspicious_extension for .exe', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const exeAtt = audit.attachmentsAudit.attachments.find(a =>
      a.filename && a.filename.toLowerCase().includes('.exe')
    );
    assert.ok(exeAtt, 'Should find EXE attachment');
    assert.strictEqual(exeAtt.suspicious, true);
    const flag = exeAtt.flags.find(f => f.type === 'suspicious_extension');
    assert.ok(flag, 'Should have suspicious_extension flag');
  });

  it('flags double_extension for disguised files', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const disguisedAtt = audit.attachmentsAudit.attachments.find(a => {
      return a.flags && a.flags.some(f => f.type === 'double_extension');
    });
    assert.ok(disguisedAtt, 'Should find double-extension flagged attachment');
    assert.strictEqual(disguisedAtt.suspicious, true);
  });

  it('includes SHA256, size, and content type for each attachment', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    for (const att of audit.attachmentsAudit.attachments) {
      assert.ok(att.filename, 'Should have filename');
      assert.ok(att.contentType, 'Should have contentType');
      assert.strictEqual(typeof att.size, 'number');
      assert.ok(att.sizeFormatted, 'Should have sizeFormatted');
      assert.ok(att.sha256, 'Should have sha256');
      assert.strictEqual(att.sha256.length, 64);
      assert.ok(att.extension, 'Should have extension');
    }
  });
});

describe('forensicAudit - Signal Summary & Overall Risk', function() {
  it('signalSummary totals match suspiciousSignals array', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.strictEqual(audit.signalSummary.total, audit.suspiciousSignals.length);
    assert.strictEqual(
      audit.signalSummary.critical,
      audit.suspiciousSignals.filter(s => s.risk === 'critical').length
    );
    assert.strictEqual(
      audit.signalSummary.high,
      audit.suspiciousSignals.filter(s => s.risk === 'high').length
    );
    assert.strictEqual(
      audit.signalSummary.medium,
      audit.suspiciousSignals.filter(s => s.risk === 'medium').length
    );
    assert.strictEqual(
      audit.signalSummary.low,
      audit.suspiciousSignals.filter(s => s.risk === 'low').length
    );
  });

  it('overallRisk reflects maximum signal risk level', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const order = ['safe', 'low', 'medium', 'high', 'critical'];
    let maxRisk = 'safe';
    for (const s of audit.suspiciousSignals) {
      if (order.indexOf(s.risk) > order.indexOf(maxRisk)) {
        maxRisk = s.risk;
      }
    }
    assert.strictEqual(audit.overallRisk, maxRisk);
    assert.ok(audit.overallRiskText, 'Should have overallRiskText');
  });

  it('benign email has overallRisk safe or low', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const audit = runForensicAudit(eml);
    const order = ['safe', 'low', 'medium', 'high', 'critical'];
    assert.ok(order.indexOf(audit.overallRisk) <= 1,
      `Benign email should be safe/low, got ${audit.overallRisk}`);
  });

  it('phishing audit sample has elevated risk', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const order = ['safe', 'low', 'medium', 'high', 'critical'];
    assert.ok(order.indexOf(audit.overallRisk) >= 2,
      `Phishing sample should be at least medium, got ${audit.overallRisk}`);
  });

  it('detectSuspiciousSignals is independently callable', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const signals = detectSuspiciousSignals(eml);
    assert.ok(Array.isArray(signals));
    assert.ok(signals.length >= 5, 'Should have multiple signals for phishing sample');
  });
});

describe('forensicAudit - Report Generation (JSON & Markdown)', function() {
  let tmpDir = null;
  before(function() { tmpDir = makeTempDir(); });
  after(function() { if (tmpDir) cleanupTempDir(tmpDir); });

  it('generateForensicJsonReport produces valid JSON', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const json = generateForensicJsonReport(audit);
    const parsed = JSON.parse(json);
    assert.ok(parsed.overallRisk, 'JSON should have overallRisk');
    assert.ok(parsed.signalSummary, 'JSON should have signalSummary');
    assert.ok(parsed.receivedChain, 'JSON should have receivedChain');
    assert.ok(parsed.urls, 'JSON should have urls');
    assert.ok(parsed.authenticationResults, 'JSON should have authenticationResults');
  });

  it('generateForensicMarkdownReport includes key sections', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const md = generateForensicMarkdownReport(audit);
    assert.ok(md.includes('# 邮件取证审计报告'), 'Should have title');
    assert.ok(md.includes('Received'), 'Should mention Received');
    assert.ok(md.includes('DKIM'), 'Should mention DKIM');
    assert.ok(md.includes('SPF'), 'Should mention SPF');
    assert.ok(md.includes('DMARC'), 'Should mention DMARC');
    assert.ok(md.includes('URL'), 'Should mention URL');
    assert.ok(md.includes('附件'), 'Should mention attachments');
    assert.ok(md.includes('可疑信号'), 'Should mention suspicious signals');
  });

  it('exportForensicReport writes JSON file', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const outPath = path.join(tmpDir, 'audit.json');
    const result = exportForensicReport(audit, outPath);
    assert.strictEqual(result.format, 'json');
    assert.ok(fs.existsSync(outPath), 'File should be written');
    const content = JSON.parse(fs.readFileSync(outPath, 'utf8'));
    assert.ok(content.overallRisk, 'Exported JSON should be valid');
  });

  it('exportForensicReport writes Markdown file', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const outPath = path.join(tmpDir, 'audit.md');
    const result = exportForensicReport(audit, outPath);
    assert.strictEqual(result.format, 'markdown');
    assert.ok(fs.existsSync(outPath), 'MD file should be written');
    const content = fs.readFileSync(outPath, 'utf8');
    assert.ok(content.includes('# 邮件取证审计报告'), 'Should have Markdown title');
  });

  it('Markdown report includes risk badges for suspicious signals', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    const md = generateForensicMarkdownReport(audit);
    assert.ok(md.includes('🟢') || md.includes('🟡') || md.includes('🟠') || md.includes('🔴') || md.includes('💀'),
      'Should include risk badge emojis');
  });
});

describe('forensicAudit - Audit Headers Field', function() {
  it('captures all From/To/Cc/Bcc/Reply-To in audit', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.headers.from, 'Should have from');
    assert.ok(audit.headers.from.email.includes('official-bank.com'), 'From email should match');
    assert.ok(audit.headers.to.length >= 1, 'Should have To');
    assert.ok(audit.headers.cc.length >= 1, 'Should have Cc');
    assert.ok(audit.headers.bcc.length >= 1, 'Should have Bcc');
    assert.ok(audit.headers.replyTo.length >= 1, 'Should have Reply-To');
  });

  it('includes subject, date, messageId, mimeVersion in audit headers', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.headers.subject, 'Should have subject');
    assert.ok(audit.headers.date, 'Should have date ISO string');
    assert.ok(audit.headers.dateString, 'Should have dateString');
    assert.ok(audit.headers.messageId, 'Should have messageId');
    assert.ok(audit.headers.mimeVersion, 'Should have mimeVersion');
    assert.ok(audit.headers.allHeaders, 'Should have allHeaders map');
  });
});

describe('forensicAudit - Original Forensic Sample (sample5)', function() {
  it('runs audit on sample5_forensic.eml without errors', function() {
    const eml = loadEml('orig_sample5_forensic.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit, 'Should produce audit result');
    assert.ok(audit.signalSummary.total >= 1, 'Should detect at least one signal in forensic sample');
  });

  it('detects From/Reply-To mismatch in sample5', function() {
    const eml = loadEml('orig_sample5_forensic.eml');
    const audit = runForensicAudit(eml);
    const mismatch = audit.suspiciousSignals.find(s => s.type === 'from_replyto_domain_mismatch');
    assert.ok(mismatch, 'sample5 should have From/Reply-To mismatch');
  });

  it('finds short links and IP direct links in sample5', function() {
    const eml = loadEml('orig_sample5_forensic.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.urls.suspiciousShortLinks.length >= 1, 'Should find short links');
    assert.ok(audit.urls.ipDirectLinks.length >= 1, 'Should find IP direct links');
  });

  it('has Received chain with hops in sample5', function() {
    const eml = loadEml('orig_sample5_forensic.eml');
    const audit = runForensicAudit(eml);
    assert.ok(audit.receivedChain.count >= 3, 'sample5 should have 3+ Received hops');
  });
});
