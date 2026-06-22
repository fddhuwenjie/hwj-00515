const assert = require('assert');
const { describe, it } = require('./harness');
const path = require('path');
const { PROJECT_ROOT, loadEml } = require('./helpers');

const { checkSecurity, RISK_LEVELS, SUSPICIOUS_EXTENSIONS, MACRO_ENABLED_EXTENSIONS, getRiskLevelText, getRiskColor } = require(path.join(PROJECT_ROOT, 'lib/securityChecker'));

describe('securityChecker - Suspicious Attachment Extension Detection', function() {
  it('detects suspicious executable extensions (.exe)', function() {
    const eml = loadEml('orig_sample4_suspicious.eml');
    const issues = eml.security.issues.filter(i => i.type === 'suspicious_extension');
    assert.ok(issues.length >= 1, 'Should detect suspicious .exe extension');
    const exeIssue = issues.find(i => i.details && i.details.filename && i.details.filename.includes('invoice'));
    assert.ok(exeIssue, 'Should find invoice.pdf.exe flagged');
    assert.strictEqual(exeIssue.risk, RISK_LEVELS.HIGH, 'Should be HIGH risk');
  });

  it('flags .exe with risk level HIGH', function() {
    const eml = loadEml('orig_sample4_suspicious.eml');
    const exeIssues = eml.security.issues.filter(i =>
      i.type === 'suspicious_extension' && i.details && i.details.extension === '.exe'
    );
    assert.ok(exeIssues.length >= 1);
    assert.strictEqual(exeIssues[0].risk, 'high');
  });

  it('SUSPICIOUS_EXTENSIONS contains common dangerous extensions', function() {
    assert.ok(SUSPICIOUS_EXTENSIONS.includes('.exe'));
    assert.ok(SUSPICIOUS_EXTENSIONS.includes('.bat'));
    assert.ok(SUSPICIOUS_EXTENSIONS.includes('.cmd'));
    assert.ok(SUSPICIOUS_EXTENSIONS.includes('.vbs'));
    assert.ok(SUSPICIOUS_EXTENSIONS.includes('.js'));
    assert.ok(SUSPICIOUS_EXTENSIONS.includes('.ps1'));
    assert.ok(SUSPICIOUS_EXTENSIONS.includes('.jar'));
  });

  it('does not flag safe extensions (.pdf, .docx, .png)', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    const suspiciousExtIssues = eml.security.issues.filter(i => i.type === 'suspicious_extension');
    assert.strictEqual(suspiciousExtIssues.length, 0, 'Safe attachments should not raise suspicious_extension');
  });
});

describe('securityChecker - Macro-Enabled Office Document Detection', function() {
  it('detects macro-enabled .docm files', function() {
    const eml = loadEml('orig_sample4_suspicious.eml');
    const macroIssues = eml.security.issues.filter(i => i.type === 'macro_enabled');
    assert.ok(macroIssues.length >= 1, 'Should detect macro-enabled document');
    assert.strictEqual(macroIssues[0].risk, RISK_LEVELS.HIGH);
  });

  it('MACRO_ENABLED_EXTENSIONS contains Office macro formats', function() {
    assert.ok(MACRO_ENABLED_EXTENSIONS.includes('.docm'));
    assert.ok(MACRO_ENABLED_EXTENSIONS.includes('.xlsm'));
    assert.ok(MACRO_ENABLED_EXTENSIONS.includes('.pptm'));
  });

  it('does not flag regular Office documents without macros', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    const macroIssues = eml.security.issues.filter(i => i.type === 'macro_enabled');
    assert.strictEqual(macroIssues.length, 0);
  });
});

describe('securityChecker - Double Extension Detection', function() {
  it('detects double extension disguise (invoice.pdf.exe)', function() {
    const eml = loadEml('orig_sample4_suspicious.eml');
    const doubleExtIssues = eml.security.issues.filter(i => i.type === 'double_extension');
    assert.ok(doubleExtIssues.length >= 1, 'Should detect double extension');
    const issue = doubleExtIssues[0];
    assert.strictEqual(issue.risk, RISK_LEVELS.CRITICAL, 'Double extension should be CRITICAL risk');
    assert.ok(issue.details.visibleExtension, 'Should have visible extension');
    assert.ok(issue.details.actualExtension, 'Should have actual extension');
    assert.strictEqual(issue.details.actualExtension, '.exe');
  });

  it('flags double extension as CRITICAL risk', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const doubleExtIssues = eml.security.issues.filter(i => i.type === 'double_extension');
    assert.ok(doubleExtIssues.length >= 1);
    assert.strictEqual(doubleExtIssues[0].risk, RISK_LEVELS.CRITICAL);
  });

  it('does not flag normal single extensions', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    const doubleExtIssues = eml.security.issues.filter(i => i.type === 'double_extension');
    assert.strictEqual(doubleExtIssues.length, 0, 'Normal filenames should not trigger double_extension');
  });

  it('does not flag files with exactly 2 name parts (e.g. report.v1.pdf)', function() {
    const eml = loadEml('07_multipart_mixed.eml');
    const doubleExtIssues = eml.security.issues.filter(i => i.type === 'double_extension');
    assert.strictEqual(doubleExtIssues.length, 0);
  });
});

describe('securityChecker - External Image (Tracking Pixel) Detection', function() {
  it('detects external images in HTML body', function() {
    const eml = loadEml('11_external_images.eml');
    const extImgIssues = eml.security.issues.filter(i => i.type === 'external_images');
    assert.ok(extImgIssues.length >= 1, 'Should detect external images');
    assert.strictEqual(extImgIssues[0].risk, RISK_LEVELS.LOW, 'Should be LOW risk');
    assert.ok(extImgIssues[0].details.urls.length >= 2, 'Should find multiple external images');
  });

  it('external_images issue includes URL list', function() {
    const eml = loadEml('11_external_images.eml');
    const extImgIssues = eml.security.issues.filter(i => i.type === 'external_images');
    const urls = extImgIssues[0].details.urls;
    assert.ok(urls.some(u => u.includes('tracker')), 'Should include tracker URL');
    assert.ok(urls.some(u => u.includes('cdn')), 'Should include CDN URL');
  });

  it('does not flag cid: inline images as external', function() {
    const eml = loadEml('orig_sample2_html_inline.eml');
    const extImgIssues = eml.security.issues.filter(i => i.type === 'external_images');
    if (extImgIssues.length > 0) {
      const urls = extImgIssues[0].details.urls;
      for (const u of urls) {
        assert.ok(!u.startsWith('cid:'), 'cid URLs should not be in external image list');
      }
    }
  });

  it('plain text emails have no external images', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const extImgIssues = eml.security.issues.filter(i => i.type === 'external_images');
    assert.strictEqual(extImgIssues.length, 0);
  });
});

describe('securityChecker - Overall Risk Assessment', function() {
  it('benign plain email has SAFE or LOW risk', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const risk = eml.security.overallRisk;
    assert.ok(
      risk === RISK_LEVELS.SAFE || risk === RISK_LEVELS.LOW,
      `Plain email should be safe/low, got ${risk}`
    );
  });

  it('suspicious email with exe and double extension has HIGH or CRITICAL risk', function() {
    const eml = loadEml('orig_sample4_suspicious.eml');
    const risk = eml.security.overallRisk;
    assert.ok(
      risk === RISK_LEVELS.HIGH || risk === RISK_LEVELS.CRITICAL,
      `Suspicious email should be high/critical, got ${risk}`
    );
  });

  it('summary counts match actual issues', function() {
    const eml = loadEml('orig_sample4_suspicious.eml');
    const s = eml.security.summary;
    assert.strictEqual(s.total, eml.security.issues.length);
    assert.strictEqual(s.critical, eml.security.issues.filter(i => i.risk === RISK_LEVELS.CRITICAL).length);
    assert.strictEqual(s.high, eml.security.issues.filter(i => i.risk === RISK_LEVELS.HIGH).length);
    assert.strictEqual(s.medium, eml.security.issues.filter(i => i.risk === RISK_LEVELS.MEDIUM).length);
    assert.strictEqual(s.low, eml.security.issues.filter(i => i.risk === RISK_LEVELS.LOW).length);
  });

  it('overall risk is the maximum of all issue risks', function() {
    const eml = loadEml('16_forensic_audit.eml');
    let maxRisk = 'safe';
    const order = ['safe', 'low', 'medium', 'high', 'critical'];
    for (const issue of eml.security.issues) {
      if (order.indexOf(issue.risk) > order.indexOf(maxRisk)) {
        maxRisk = issue.risk;
      }
    }
    assert.strictEqual(eml.security.overallRisk, maxRisk);
  });
});

describe('securityChecker - Helper Functions', function() {
  it('getRiskLevelText returns Chinese labels', function() {
    assert.strictEqual(getRiskLevelText('safe'), '安全');
    assert.strictEqual(getRiskLevelText('low'), '低风险');
    assert.strictEqual(getRiskLevelText('medium'), '中风险');
    assert.strictEqual(getRiskLevelText('high'), '高风险');
    assert.strictEqual(getRiskLevelText('critical'), '严重风险');
  });

  it('getRiskColor returns color names', function() {
    assert.strictEqual(getRiskColor('safe'), 'green');
    assert.strictEqual(getRiskColor('low'), 'yellow');
    assert.strictEqual(getRiskColor('medium'), 'orange');
    assert.strictEqual(getRiskColor('high'), 'red');
    assert.strictEqual(getRiskColor('critical'), 'red');
    assert.strictEqual(getRiskColor('unknown'), 'gray');
  });

  it('RISK_LEVELS enum has all expected levels', function() {
    assert.strictEqual(RISK_LEVELS.SAFE, 'safe');
    assert.strictEqual(RISK_LEVELS.LOW, 'low');
    assert.strictEqual(RISK_LEVELS.MEDIUM, 'medium');
    assert.strictEqual(RISK_LEVELS.HIGH, 'high');
    assert.strictEqual(RISK_LEVELS.CRITICAL, 'critical');
  });
});

describe('securityChecker - Header-Based Checks', function() {
  it('detects X-Mailer PHP mailer indicator', function() {
    const eml = loadEml('16_forensic_audit.eml');
    const bulkIssues = eml.security.issues.filter(i => i.type === 'bulk_mailer');
    assert.ok(bulkIssues.length >= 1, 'Should detect PHP bulk mailer');
    assert.strictEqual(bulkIssues[0].risk, RISK_LEVELS.LOW);
  });
});
