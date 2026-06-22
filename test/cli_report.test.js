const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const assert = require('assert');
const { describe, it, before, after } = require('./harness');
const { PROJECT_ROOT, SAMPLES_DIR, makeTempDir, cleanupTempDir } = require('./helpers');

const { generateReport, generateJsonReport, generateMarkdownReport, exportReport } = require(path.join(PROJECT_ROOT, 'lib/reportGenerator'));
const { loadEml } = require('./helpers');

function runCli(args, opts = {}) {
  const cmd = `node ${path.join(PROJECT_ROOT, 'emltool.js')} ${args}`;
  try {
    return execSync(cmd, {
      cwd: PROJECT_ROOT,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      ...opts
    });
  } catch (e) {
    return e.stdout + e.stderr;
  }
}

describe('reportGenerator - Report Generation', function() {
  it('generateJsonReport produces valid JSON with all sections', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    const json = generateJsonReport(eml);
    const report = JSON.parse(json);

    assert.ok(report.generatedAt, 'Should have generatedAt timestamp');
    assert.ok(report.file, 'Should have file path');
    assert.ok(report.headers, 'Should have headers');
    assert.ok(report.headers.from, 'Should have From header');
    assert.ok(report.mimeTree, 'Should have mimeTree');
    assert.ok(report.body, 'Should have body info');
    assert.ok(report.attachments, 'Should have attachments array');
    assert.ok(report.security, 'Should have security info');
  });

  it('generateJsonReport attachments include SHA256 and metadata', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    const json = generateJsonReport(eml);
    const report = JSON.parse(json);
    assert.ok(report.attachments.length >= 3);
    for (const att of report.attachments) {
      assert.ok(att.filename);
      assert.ok(att.contentType);
      assert.strictEqual(typeof att.size, 'number');
      assert.ok(att.sha256);
      assert.strictEqual(att.sha256.length, 64);
    }
  });

  it('generateMarkdownReport includes all major sections', function() {
    const eml = loadEml('orig_sample3_multi_attach.eml');
    const md = generateMarkdownReport(eml);
    assert.ok(md.includes('# 邮件分析报告'), 'Should have title');
    assert.ok(md.includes('邮件头信息'), 'Should have headers section');
    assert.ok(md.includes('MIME 结构'), 'Should have MIME section');
    assert.ok(md.includes('正文摘要'), 'Should have body section');
    assert.ok(md.includes('附件列表'), 'Should have attachments section');
    assert.ok(md.includes('安全风险分析'), 'Should have security section');
  });

  it('generateReport dispatches by format parameter', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const jsonStr = generateReport(eml, 'json');
    const mdStr = generateReport(eml, 'markdown');
    const mdStr2 = generateReport(eml, 'md');

    JSON.parse(jsonStr);
    assert.ok(mdStr.startsWith('#'));
    assert.ok(mdStr2.startsWith('#'));
  });

  let tmpDir = null;
  before(function() { tmpDir = makeTempDir(); });
  after(function() { if (tmpDir) cleanupTempDir(tmpDir); });

  it('exportReport writes JSON file', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const out = path.join(tmpDir, 'report.json');
    const result = exportReport(eml, out);
    assert.strictEqual(result.format, 'json');
    assert.ok(fs.existsSync(out));
    JSON.parse(fs.readFileSync(out, 'utf8'));
  });

  it('exportReport writes Markdown file', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    const out = path.join(tmpDir, 'report.md');
    const result = exportReport(eml, out);
    assert.strictEqual(result.format, 'markdown');
    assert.ok(fs.existsSync(out));
    const content = fs.readFileSync(out, 'utf8');
    assert.ok(content.includes('# 邮件分析报告'));
  });
});

describe('CLI Integration - inspect command', function() {
  it('shows help with -h flag', function() {
    const output = runCli('-h');
    assert.ok(output.includes('用法'), 'Should show usage in Chinese');
    assert.ok(output.includes('inspect'), 'Should list inspect command');
    assert.ok(output.includes('extract'), 'Should list extract command');
    assert.ok(output.includes('report'), 'Should list report command');
    assert.ok(output.includes('audit'), 'Should list audit command');
  });

  it('inspects sample1 plain email successfully', function() {
    const emlPath = path.join(SAMPLES_DIR, 'orig_sample1_plain.eml');
    const output = runCli(`inspect "${emlPath}"`);
    assert.ok(output.includes('邮件检查报告'), 'Should show report title');
    assert.ok(output.includes('zhangsan@example.com'), 'Should show From address');
    assert.ok(output.includes('lisi@example.com'), 'Should show To address');
    assert.ok(output.includes('你好，这是一封纯文本测试邮件'), 'Should show decoded subject');
    assert.ok(output.includes('text/plain'), 'Should show MIME content type');
    assert.ok(output.includes('无附件'), 'Should show no attachments');
  });

  it('inspects sample3 with multiple attachments', function() {
    const emlPath = path.join(SAMPLES_DIR, 'orig_sample3_multi_attach.eml');
    const output = runCli(`inspect "${emlPath}"`);
    assert.ok(output.includes('附件'), 'Should mention attachments');
    assert.ok(output.match(/共 \d+ 个附件/), 'Should show attachment count');
    assert.ok(output.includes('SHA256'), 'Should show SHA256 hashes');
    assert.ok(output.includes('风险等级'), 'Should show risk level');
  });
});

describe('CLI Integration - extract command', function() {
  let tmpDir = null;
  before(function() { tmpDir = makeTempDir(); });
  after(function() { if (tmpDir) cleanupTempDir(tmpDir); });

  it('extracts attachments to output directory', function() {
    const emlPath = path.join(SAMPLES_DIR, 'orig_sample3_multi_attach.eml');
    const outDir = path.join(tmpDir, 'extracted');
    const output = runCli(`extract "${emlPath}" -o "${outDir}"`);

    assert.ok(output.includes('附件提取'), 'Should show extraction title');
    assert.ok(output.match(/找到 \d+ 个附件/), 'Should show found count');

    const files = fs.readdirSync(outDir);
    assert.ok(files.length >= 3, `Should extract at least 3 files, got ${files.length}`);
    for (const f of files) {
      const stat = fs.statSync(path.join(outDir, f));
      assert.ok(stat.size > 0, `File ${f} should be non-empty`);
    }
  });

  it('extract without -o uses default ./attachments (sample output check)', function() {
    const emlPath = path.join(SAMPLES_DIR, '07_multipart_mixed.eml');
    const output = runCli(`extract "${emlPath}" -o "${tmpDir}/default_test"`);
    assert.ok(output.includes('完成'), 'Should show completion');
  });
});

describe('CLI Integration - report command', function() {
  let tmpDir = null;
  before(function() { tmpDir = makeTempDir(); });
  after(function() { if (tmpDir) cleanupTempDir(tmpDir); });

  it('generates JSON report to stdout', function() {
    const emlPath = path.join(SAMPLES_DIR, 'orig_sample1_plain.eml');
    const output = runCli(`report "${emlPath}"`);
    const report = JSON.parse(output.slice(output.indexOf('{'), output.lastIndexOf('}') + 1));
    assert.ok(report.headers, 'Should have headers in JSON report');
  });

  it('generates JSON report to file', function() {
    const emlPath = path.join(SAMPLES_DIR, 'orig_sample3_multi_attach.eml');
    const outFile = path.join(tmpDir, 'out.json');
    runCli(`report "${emlPath}" -o "${outFile}"`);
    assert.ok(fs.existsSync(outFile));
    const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    assert.ok(report.attachments.length >= 3);
  });

  it('generates Markdown report to file', function() {
    const emlPath = path.join(SAMPLES_DIR, 'orig_sample3_multi_attach.eml');
    const outFile = path.join(tmpDir, 'out.md');
    runCli(`report "${emlPath}" -o "${outFile}"`);
    assert.ok(fs.existsSync(outFile));
    const content = fs.readFileSync(outFile, 'utf8');
    assert.ok(content.includes('# 邮件分析报告'));
  });
});

describe('CLI Integration - audit command', function() {
  let tmpDir = null;
  before(function() { tmpDir = makeTempDir(); });
  after(function() { if (tmpDir) cleanupTempDir(tmpDir); });

  it('runs audit on forensic sample and outputs summary', function() {
    const emlPath = path.join(SAMPLES_DIR, '16_forensic_audit.eml');
    const output = runCli(`audit "${emlPath}"`);
    assert.ok(output.includes('邮件取证审计'), 'Should have audit title');
    assert.ok(output.includes('总体风险等级'), 'Should show overall risk');
    assert.ok(output.includes('可疑信号'), 'Should show signal count');
    assert.ok(output.includes('Received 链路'), 'Should mention Received chain');
    assert.ok(output.includes('URL 数量'), 'Should mention URL count');
  });

  it('exports audit JSON report to file', function() {
    const emlPath = path.join(SAMPLES_DIR, '16_forensic_audit.eml');
    const outFile = path.join(tmpDir, 'audit.json');
    runCli(`audit "${emlPath}" -o "${outFile}"`);
    assert.ok(fs.existsSync(outFile));
    const audit = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    assert.ok(audit.overallRisk);
    assert.ok(audit.signalSummary);
    assert.ok(audit.receivedChain);
    assert.ok(audit.urls);
    assert.ok(audit.authenticationResults);
    assert.ok(audit.attachmentsAudit);
  });

  it('exports audit Markdown report to file', function() {
    const emlPath = path.join(SAMPLES_DIR, '16_forensic_audit.eml');
    const outFile = path.join(tmpDir, 'audit.md');
    runCli(`audit "${emlPath}" -o "${outFile}"`);
    assert.ok(fs.existsSync(outFile));
    const content = fs.readFileSync(outFile, 'utf8');
    assert.ok(content.includes('# 邮件取证审计报告'));
    assert.ok(content.includes('Received'));
    assert.ok(content.includes('DKIM'));
    assert.ok(content.includes('SPF'));
    assert.ok(content.includes('DMARC'));
  });

  it('audit sample5 produces signal counts', function() {
    const emlPath = path.join(SAMPLES_DIR, 'orig_sample5_forensic.eml');
    const output = runCli(`audit "${emlPath}"`);
    assert.ok(output.includes('总体风险等级'));
    assert.ok(output.match(/可疑信号: \d+ 个/), 'Should show signal count');
  });
});

describe('Regression Tests', function() {
  it('sample1 - full parse pipeline produces expected header fields', function() {
    const eml = loadEml('orig_sample1_plain.eml');
    assert.strictEqual(eml.headers.from.email, 'zhangsan@example.com');
    assert.strictEqual(eml.headers.from.name, '张三');
    assert.strictEqual(eml.headers.to.length, 2);
    assert.strictEqual(eml.headers.to[0].email, 'lisi@example.com');
    assert.strictEqual(eml.headers.subject, '你好，这是一封纯文本测试邮件');
    assert.strictEqual(eml.headers.messageId, '<plain-email-001@example.com>');
    assert.ok(eml.bodies.text.includes('这是一封纯文本测试邮件'));
    assert.strictEqual(eml.attachments.length, 0);
  });

  it('sample2 - inline image with cid is detected', function() {
    const eml = loadEml('orig_sample2_html_inline.eml');
    const { extractInlineImages } = require(path.join(PROJECT_ROOT, 'lib/bodyExtractor'));
    const images = extractInlineImages(eml.mimeTree);
    assert.ok(images.length >= 1, 'Should extract inline images');
    assert.strictEqual(images[0].cid, 'logo_image');
  });

  it('sample2 - external tracking image URL is detected', function() {
    const eml = loadEml('orig_sample2_html_inline.eml');
    const sec = eml.security.issues.filter(i => i.type === 'external_images');
    if (sec.length > 0) {
      assert.ok(sec[0].details.urls.some(u => u.includes('tracker.gif')),
        'Should detect tracker.gif URL');
    }
  });

  it('sample4 - suspicious attachments raise correct issue types', function() {
    const eml = loadEml('orig_sample4_suspicious.eml');
    const types = eml.security.issues.map(i => i.type);
    assert.ok(types.includes('suspicious_extension'), 'Should have suspicious_extension');
    assert.ok(types.includes('macro_enabled'), 'Should have macro_enabled');
    assert.ok(types.includes('double_extension'), 'Should have double_extension');
  });

  it('sample5 - all CLI commands run without errors', function() {
    const emlPath = path.join(SAMPLES_DIR, 'orig_sample5_forensic.eml');
    const inspectOut = runCli(`inspect "${emlPath}"`);
    assert.ok(inspectOut.includes('邮件检查报告'));

    const reportOut = runCli(`report "${emlPath}" -f json`);
    assert.ok(reportOut.includes('generatedAt'));

    const auditOut = runCli(`audit "${emlPath}"`);
    assert.ok(auditOut.includes('邮件取证审计'));
  });

  it('all test samples can be parsed without throwing', function() {
    const sampleFiles = [
      '01_header_crlf.eml',
      '02_header_lf.eml',
      '03_folded_headers.eml',
      '04_gbk_encoded.eml',
      '05_plain_base64.eml',
      '06_plain_qp.eml',
      '07_multipart_mixed.eml',
      '08_multipart_alternative.eml',
      '09_multipart_related.eml',
      '10_duplicate_filenames.eml',
      '11_external_images.eml',
      '12_address_edge.eml',
      '13_minimal_headers.eml',
      '14_empty_subject.eml',
      '15_rfc2047_mixed.eml',
      '16_forensic_audit.eml',
      '17_rfc2231_filename.eml',
      '18_missing_messageid.eml'
    ];

    for (const f of sampleFiles) {
      let eml;
      try {
        eml = loadEml(f);
      } catch (e) {
        assert.fail(`Failed to parse ${f}: ${e.message}`);
      }
      assert.ok(eml.headers, `${f}: Should have headers`);
      assert.ok(eml.mimeTree, `${f}: Should have mimeTree`);
    }
  });
});
