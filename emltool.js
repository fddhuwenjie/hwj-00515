#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const { parseHeaders, extractEmailHeaders } = require('./lib/headerParser');
const { parseMimeStructure, formatMimeTree, formatSize } = require('./lib/mimeParser');
const { extractBodies, htmlToPlainText, extractExternalImageUrls } = require('./lib/bodyExtractor');
const { extractAttachments, listAttachments } = require('./lib/attachmentExtractor');
const { checkSecurity, getRiskLevelText, getRiskColor } = require('./lib/securityChecker');
const { generateReport, exportReport, generateJsonReport, generateMarkdownReport } = require('./lib/reportGenerator');

function loadEml(filePath) {
  if (!fs.existsSync(filePath)) {
    console.error(`错误: 文件不存在: ${filePath}`);
    process.exit(1);
  }

  const rawContent = fs.readFileSync(filePath, 'latin1');
  const headerData = parseHeaders(rawContent);
  const headers = extractEmailHeaders(headerData);
  const mimeTree = parseMimeStructure(rawContent);
  const bodies = extractBodies(mimeTree);

  let htmlAsText = null;
  if (bodies.html) {
    htmlAsText = htmlToPlainText(bodies.html);
  }

  bodies.htmlAsText = htmlAsText;

  const attachments = listAttachments(mimeTree);

  const emlData = {
    file: path.resolve(filePath),
    rawContent,
    headers,
    mimeTree,
    bodies,
    attachments
  };

  emlData.security = checkSecurity(emlData);

  return emlData;
}

function printUsage() {
  console.log(`
emltool - EML 邮件 MIME 解析和附件提取工具

用法:
  node emltool.js <command> <file.eml> [options]

命令:
  inspect <file.eml>        查看邮件基本信息和 MIME 结构
  extract <file.eml>        提取邮件附件
    -o, --output <dir>      输出目录 (默认: ./attachments)

  report <file.eml>         生成分析报告
    -o, --output <file>     输出文件路径 (.json 或 .md)
    -f, --format <format>   报告格式: json 或 markdown (默认根据扩展名推断)

示例:
  node emltool.js inspect mail.eml
  node emltool.js extract mail.eml -o attachments/
  node emltool.js report mail.eml -o report.md
  node emltool.js report mail.eml -o report.json
`);
}

function parseArgs(args) {
  const result = {
    command: null,
    file: null,
    options: {}
  };

  let i = 0;

  if (i < args.length && !args[i].startsWith('-')) {
    result.command = args[i];
    i++;
  }

  if (i < args.length && !args[i].startsWith('-')) {
    result.file = args[i];
    i++;
  }

  while (i < args.length) {
    const arg = args[i];

    if (arg === '-o' || arg === '--output') {
      i++;
      if (i < args.length) {
        result.options.output = args[i];
      }
    } else if (arg === '-f' || arg === '--format') {
      i++;
      if (i < args.length) {
        result.options.format = args[i];
      }
    } else {
      result.options[arg] = true;
    }

    i++;
  }

  return result;
}

function cmdInspect(emlData) {
  const h = emlData.headers;

  console.log('\n' + '='.repeat(60));
  console.log('  邮件检查报告');
  console.log('='.repeat(60) + '\n');

  console.log('【邮件头】');
  console.log('  发件人:    ' + (h.from ? formatAddress(h.from) : '(无)'));
  console.log('  收件人:    ' + (h.to && h.to.length > 0 ? h.to.map(a => formatAddress(a)).join(', ') : '(无)'));
  if (h.cc && h.cc.length > 0) {
    console.log('  抄送:      ' + h.cc.map(a => formatAddress(a)).join(', '));
  }
  if (h.replyTo && h.replyTo.length > 0) {
    console.log('  回复:      ' + h.replyTo.map(a => formatAddress(a)).join(', '));
  }
  console.log('  主题:      ' + (h.subject || '(无主题)'));
  console.log('  日期:      ' + (h.dateString || '(无)'));
  console.log('  Message-ID: ' + (h.messageId || '(无)'));
  console.log('');

  console.log('【MIME 结构】');
  const treeLines = formatMimeTree(emlData.mimeTree);
  treeLines.forEach(line => console.log('  ' + line));
  console.log('');

  console.log('【正文】');
  const hasText = !!emlData.bodies.text;
  const hasHtml = !!emlData.bodies.html;
  console.log('  text/plain: ' + (hasText ? '有' : '无') + (hasText ? ` (${formatSize(Buffer.byteLength(emlData.bodies.text, 'utf8'))})` : ''));
  console.log('  text/html:  ' + (hasHtml ? '有' : '无') + (hasHtml ? ` (${formatSize(Buffer.byteLength(emlData.bodies.html, 'utf8'))})` : ''));

  const summary = emlData.bodies.text || emlData.bodies.htmlAsText || '';
  if (summary) {
    const shortSummary = summary.replace(/\s+/g, ' ').trim().substring(0, 100);
    console.log('  摘要:       ' + shortSummary + (shortSummary.length < summary.length ? '...' : ''));
  }
  console.log('');

  console.log('【附件】');
  if (emlData.attachments.length === 0) {
    console.log('  无附件');
  } else {
    console.log(`  共 ${emlData.attachments.length} 个附件:\n`);
    emlData.attachments.forEach((att, i) => {
      console.log(`  ${i + 1}. ${att.filename}`);
      console.log(`     类型: ${att.contentType}  大小: ${att.sizeFormatted}`);
      if (att.contentId) console.log(`     CID: ${att.contentId}`);
      console.log(`     SHA256: ${att.sha256.substring(0, 32)}...`);
    });
  }
  console.log('');

  console.log('【安全检查】');
  const sec = emlData.security;
  console.log('  风险等级: ' + formatRiskBadge(sec.overallRisk));
  console.log('  问题数量: ' + sec.issues.length);

  if (sec.issues.length > 0) {
    console.log('');
    sec.issues.forEach((issue, i) => {
      console.log(`  ${i + 1}. [${formatRiskBadge(issue.risk)}] ${issue.description}`);
    });
  }

  console.log('\n' + '='.repeat(60) + '\n');
}

function cmdExtract(emlData, options) {
  const outputDir = options.output || './attachments';
  const absOutputDir = path.resolve(outputDir);

  console.log('\n' + '='.repeat(60));
  console.log('  附件提取');
  console.log('='.repeat(60) + '\n');

  if (emlData.attachments.length === 0) {
    console.log('  邮件中没有附件。\n');
    return;
  }

  console.log(`  找到 ${emlData.attachments.length} 个附件\n`);
  console.log(`  输出目录: ${absOutputDir}\n`);

  const results = extractAttachments(emlData.mimeTree, absOutputDir);

  results.forEach((result, i) => {
    console.log(`  ${i + 1}. ✓ ${result.filename}`);
    console.log(`     大小: ${result.sizeFormatted}`);
    console.log(`     SHA256: ${result.sha256}`);
    console.log('');
  });

  console.log(`  完成! 共提取 ${results.length} 个附件\n`);
}

function cmdReport(emlData, options) {
  const output = options.output;
  const format = options.format || (output ? path.extname(output).slice(1) : 'json');

  console.log('\n' + '='.repeat(60));
  console.log('  生成报告');
  console.log('='.repeat(60) + '\n');

  if (output) {
    const absOutput = path.resolve(output);
    const result = exportReport(emlData, absOutput);
    console.log(`  报告格式: ${result.format.toUpperCase()}`);
    console.log(`  输出文件: ${absOutput}`);
    console.log(`  状态: ✓ 生成成功`);
  } else {
    const report = format === 'markdown' || format === 'md'
      ? generateMarkdownReport(emlData)
      : generateJsonReport(emlData);
    console.log(report);
  }

  console.log('\n' + '='.repeat(60) + '\n');
}

function formatAddress(addr) {
  if (!addr) return '';
  if (addr.name) {
    return `"${addr.name}" <${addr.email}>`;
  }
  return addr.email;
}

function formatRiskBadge(level) {
  const badges = {
    safe: '✓ 安全',
    low: '⚠ 低风险',
    medium: '⚡ 中风险',
    high: '✗ 高风险',
    critical: '💀 严重风险'
  };
  return badges[level] || level;
}

function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    printUsage();
    process.exit(0);
  }

  const parsed = parseArgs(args);

  if (!parsed.command) {
    console.error('错误: 缺少命令。使用 -h 查看帮助。');
    process.exit(1);
  }

  if (!parsed.file) {
    console.error('错误: 缺少邮件文件路径。');
    process.exit(1);
  }

  const emlData = loadEml(parsed.file);

  switch (parsed.command) {
    case 'inspect':
      cmdInspect(emlData);
      break;
    case 'extract':
      cmdExtract(emlData, parsed.options);
      break;
    case 'report':
      cmdReport(emlData, parsed.options);
      break;
    default:
      console.error(`错误: 未知命令 '${parsed.command}'`);
      printUsage();
      process.exit(1);
  }
}

main();
