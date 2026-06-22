# emltool - EML 邮件解析与取证审计 CLI

一个功能强大的 `.eml` 邮件 MIME 解析和附件提取命令行工具，支持头信息解析、MIME 层级处理、正文解码、附件提取、安全检查和取证审计报告生成。

## 功能特性

- **邮件头解析**：From、To、Cc、Bcc、Reply-To、Subject、Date、Message-ID 等
- **RFC 2047 编码**：支持 Base64 / Quoted-Printable encoded-word 解码
- **折行 Header 展开**：正确处理多行折叠的邮件头
- **多种换行风格**：自动识别 CRLF (Windows) 和 LF (Unix) 邮件头结束位置
- **MIME 层级解析**：multipart/mixed、multipart/alternative、multipart/related 嵌套结构
- **多编码正文解码**：base64、quoted-printable、UTF-8、GBK 等字符集
- **附件处理**：提取、重名自动改名、SHA256 计算、内联图片 CID 识别
- **安全检测**：可疑扩展名、宏文件、双扩展名、外链追踪图片风险检测
- **取证审计 (audit)**：
  - Received 链路倒序分析与延迟计算
  - From 与 Reply-To 域名不一致检测
  - Message-ID 域名异常检测
  - Date 与 Received 时间偏差检测
  - DKIM / SPF / DMARC 认证结果解析
  - 正文 URL、外部图片、短链、IP 直连提取
  - 附件内嵌链接提取

## 安装

无需额外依赖，仅需 Node.js (v14+)。

```bash
npm install
```

## 命令使用

```bash
# 查看邮件基本信息和 MIME 结构
node emltool.js inspect samples/sample1_plain.eml

# 提取附件到指定目录
node emltool.js extract samples/sample3_multi_attach.eml -o ./attachments

# 生成分析报告 (JSON 或 Markdown)
node emltool.js report samples/sample1_plain.eml -o report.json
node emltool.js report samples/sample1_plain.eml -o report.md

# 取证审计 (输出 JSON 或 Markdown 审计报告)
node emltool.js audit samples/sample5_forensic.eml
node emltool.js audit samples/sample5_forensic.eml -o audit.json
node emltool.js audit samples/sample5_forensic.eml -o audit.md
```

## 自动化测试

### 运行方式

```bash
# 一键运行全部测试
npm test

# 只生成测试样本 (不运行测试)
npm run test:gen-samples
```

### 预期通过标准

运行 `npm test` 后预期输出应包含：

```
✓ All tests passed!

TEST SUMMARY
============================================================
  Suites:   15
  Total:    XXX
  Passed:   XXX (green)
  Failed:   0
```

- 所有测试必须 100% 通过 (Failed = 0)
- 若测试失败，脚本会以非零退出码 (exit 1) 结束
- 失败的测试会在输出底部显示 FAILURES 详情，包含套件名、用例名和堆栈信息

### 测试覆盖范围

测试体系分为以下模块，位于 `test/` 目录：

| 测试文件 | 覆盖内容 |
|----------|----------|
| `headerParser.test.js` | 头结束位置识别 (CRLF/LF)、RFC 2047 encoded-word 解码、折行 header 展开、From/To/Cc/Bcc/Reply-To 地址列表解析、Subject/Date/Message-ID 解析、GBK/UTF-8 字符集解码、最小化头信息、空主题 |
| `mimeParser.test.js` | base64 / quoted-printable / 7bit / 8bit 正文解码、multipart/mixed / alternative / related 层级解析、Content-Type 参数解析、Content-Disposition 与 Content-ID 提取、RFC 2231 文件名编码、HTML 转纯文本、外部图片 URL 提取、内联图片 cid 识别 |
| `attachmentExtractor.test.js` | 附件列表与元数据、SHA256 校验、文件名清洗 (非法字符/过长/空)、重名附件自动冲突解决 (大小写不敏感)、文件写入磁盘验证、Content-ID 内联图提取 |
| `securityChecker.test.js` | 可疑扩展名 (.exe/.bat/.js 等)、宏启用 Office 文档 (.docm/.xlsm/.pptm)、双扩展名伪装 (invoice.pdf.exe)、外部追踪图片、邮件头批量发送工具标记、总体风险等级聚合、风险文本/颜色标签 |
| `forensicAudit.test.js` | Received 链路倒序与延迟计算、From/Reply-To 域名不一致、Message-ID IP 域名异常、Date/Received 时间偏差、DKIM/SPF/DMARC 认证、文本/HTML/附件 URL 提取、短链检测、IP 直连检测、外部图片、主题/正文钓鱼语言、附件安全审计、信号汇总与总体风险、JSON/Markdown 报告导出、sample5 原始取证样本验证 |
| `cli_report.test.js` | reportGenerator JSON/Markdown 报告、CLI inspect/extract/report/audit 命令集成、回归测试 (5 个原始样本 + 18 个测试样本全量解析) |

### 测试样本

`test/samples/` 目录包含 23+ 个 EML 邮件样本：

- **正常样例**：纯文本、HTML + 内联图、多附件、multipart alternative/related
- **异常边界样例**：LF 换行、CRLF 换行、折行头、空主题、缺失 Message-ID、GBK 编码、RFC 2231 文件名、复杂地址列表（引号/逗号/转义）、重名附件
- **安全/取证样例**：可疑 EXE 附件、宏文档、双扩展名伪装、外部追踪像素、From/Reply-To 域名不一致、IP 直链、短链 (bit.ly / goo.gl / tinyurl)、DKIM/SPF/DMARC 头、Received 多跳链路、钓鱼语言

原始 `samples/` 目录下的 5 封邮件会被自动复制为 `orig_*.eml` 参与测试。

### 测试框架

使用自研轻量级 BDD 测试运行器 (`test/runner.js`)，仅依赖 Node.js 内置 `assert` 模块，无需安装任何第三方测试库。支持 `describe` / `it` / `before` / `after` / `beforeEach` / `afterEach`，输出彩色格式化结果。

### 添加新测试

1. 在 `test/` 目录下创建 `*.test.js` 文件
2. 使用 `describe('suite name', function() { it('test', function() { ... }) })` 编写用例
3. 运行 `npm test` 自动加载所有 `*.test.js`
4. 若需要新的 EML 样本，在 `test/generate_test_samples.js` 中添加生成逻辑后运行 `npm run test:gen-samples`
