const { parseHeaders, iconvDecode } = require('./headerParser');
const { Buffer } = require('buffer');

function parseMimeStructure(rawContent) {
  const headerData = parseHeaders(rawContent);
  const topLevelHeaders = parseContentTypeAndDisposition(headerData);
  const bodyContent = rawContent.substring(headerData.bodyStart);

  const tree = buildMimeTree(bodyContent, topLevelHeaders, 0);
  return tree;
}

function parseContentTypeAndDisposition(headerData) {
  const result = {
    headers: headerData.headers,
    get: headerData.get,
    getFirst: headerData.getFirst,
    contentType: 'text/plain',
    charset: 'us-ascii',
    boundary: null,
    contentTransferEncoding: '7bit',
    contentDisposition: null,
    filename: null,
    contentId: null
  };

  const contentType = headerData.getFirst('content-type');
  if (contentType) {
    const parsed = parseContentTypeHeader(contentType);
    result.contentType = parsed.type.toLowerCase();
    result.charset = (parsed.params.charset || 'us-ascii').toLowerCase();
    result.boundary = parsed.params.boundary || null;
    if (parsed.params.name) {
      result.filename = parsed.params.name;
    }
  }

  const cte = headerData.getFirst('content-transfer-encoding');
  if (cte) {
    result.contentTransferEncoding = cte.toLowerCase();
  }

  const cd = headerData.getFirst('content-disposition');
  if (cd) {
    const parsed = parseContentDisposition(cd);
    result.contentDisposition = parsed.type.toLowerCase();
    if (parsed.params.filename) {
      result.filename = parsed.params.filename;
    }
  }

  const cid = headerData.getFirst('content-id');
  if (cid) {
    result.contentId = cid.replace(/^<|>$/g, '');
  }

  return result;
}

function parseContentTypeHeader(header) {
  const parts = header.split(';');
  const type = parts[0].trim();
  const params = {};

  for (let i = 1; i < parts.length; i++) {
    const param = parts[i].trim();
    const eqIndex = param.indexOf('=');
    if (eqIndex !== -1) {
      let key = param.substring(0, eqIndex).trim().toLowerCase();
      let value = param.substring(eqIndex + 1).trim();

      if (value.startsWith('"') && value.endsWith('"')) {
        value = value.slice(1, -1);
      }

      if (key.endsWith('*')) {
        key = key.slice(0, -1);
        value = decodeRFC2231(value);
      }

      params[key] = value;
    }
  }

  return { type, params };
}

function parseContentDisposition(header) {
  return parseContentTypeHeader(header);
}

function decodeRFC2231(value) {
  try {
    const match = value.match(/^([^']*)'[^']*'(.+)$/);
    if (match) {
      const charset = match[1] || 'utf-8';
      const encoded = match[2];
      const decoded = decodePercentEncoding(encoded);
      return iconvDecode(Buffer.from(decoded, 'latin1'), charset);
    }
  } catch (e) {}
  return value;
}

function decodePercentEncoding(str) {
  let result = '';
  for (let i = 0; i < str.length; i++) {
    if (str[i] === '%' && i + 2 < str.length) {
      const hex = str.substring(i + 1, i + 3);
      result += String.fromCharCode(parseInt(hex, 16));
      i += 2;
    } else {
      result += str[i];
    }
  }
  return result;
}

function buildMimeTree(bodyContent, partInfo, depth) {
  const node = {
    contentType: partInfo.contentType,
    charset: partInfo.charset,
    contentTransferEncoding: partInfo.contentTransferEncoding,
    contentDisposition: partInfo.contentDisposition,
    filename: partInfo.filename,
    contentId: partInfo.contentId,
    depth,
    size: Buffer.byteLength(bodyContent, 'utf8'),
    children: [],
    body: bodyContent,
    headers: partInfo.headers
  };

  if (partInfo.contentType.startsWith('multipart/') && partInfo.boundary) {
    const parts = splitMultipart(bodyContent, partInfo.boundary);
    for (const partBody of parts) {
      const partHeaderData = parseHeaders(partBody);
      const childPartInfo = parseContentTypeAndDisposition(partHeaderData);
      const childBody = partBody.substring(partHeaderData.bodyStart);
      const childNode = buildMimeTree(childBody, childPartInfo, depth + 1);
      node.children.push(childNode);
    }
    node.body = null;
    node.size = Buffer.byteLength(bodyContent, 'utf8');
  }

  return node;
}

function splitMultipart(content, boundary) {
  const boundaryLine = `--${boundary}`;
  const endBoundary = `--${boundary}--`;

  const parts = [];
  let currentIndex = 0;

  let firstBoundary = content.indexOf(boundaryLine);
  if (firstBoundary === -1) {
    firstBoundary = content.indexOf('--' + boundary);
  }

  if (firstBoundary === -1) return parts;

  currentIndex = content.indexOf('\n', firstBoundary) + 1;

  while (currentIndex < content.length) {
    const nextBoundaryIdx = findNextBoundary(content, boundary, currentIndex);

    if (nextBoundaryIdx === -1) break;

    let partContent = content.substring(currentIndex, nextBoundaryIdx);
    partContent = partContent.replace(/\r?\n$/, '');

    parts.push(partContent);

    const afterBoundary = content.substring(nextBoundaryIdx);
    if (afterBoundary.startsWith(endBoundary) || afterBoundary.startsWith('--' + boundary + '--')) {
      break;
    }

    const newlineIdx = content.indexOf('\n', nextBoundaryIdx);
    if (newlineIdx === -1) break;
    currentIndex = newlineIdx + 1;
  }

  return parts;
}

function findNextBoundary(content, boundary, startIndex) {
  const patterns = [
    `\r\n--${boundary}`,
    `\n--${boundary}`,
    `\r\n--${boundary}--`,
    `\n--${boundary}--`
  ];

  let minIndex = -1;
  for (const pattern of patterns) {
    const idx = content.indexOf(pattern, startIndex);
    if (idx !== -1 && (minIndex === -1 || idx < minIndex)) {
      minIndex = idx;
    }
  }

  return minIndex;
}

function decodeContent(body, encoding, charset) {
  const enc = (encoding || '7bit').toLowerCase();
  let buffer;

  switch (enc) {
    case 'base64':
      const cleanBase64 = body.replace(/\s+/g, '');
      buffer = Buffer.from(cleanBase64, 'base64');
      break;
    case 'quoted-printable':
      buffer = decodeQuotedPrintable(body);
      break;
    case '7bit':
    case '8bit':
    case 'binary':
    default:
      buffer = Buffer.from(body, 'latin1');
      break;
  }

  return {
    buffer,
    text: charset ? iconvDecode(buffer, charset) : buffer.toString('utf8')
  };
}

function decodeQuotedPrintable(str) {
  let result = '';
  let i = 0;

  while (i < str.length) {
    if (str[i] === '=') {
      if (i + 1 < str.length && (str[i + 1] === '\n' || str[i + 1] === '\r')) {
        if (str[i + 1] === '\r' && str[i + 2] === '\n') {
          i += 3;
        } else {
          i += 2;
        }
      } else if (i + 2 < str.length) {
        const hex = str.substring(i + 1, i + 3);
        result += String.fromCharCode(parseInt(hex, 16));
        i += 3;
      } else {
        result += str[i];
        i++;
      }
    } else {
      result += str[i];
      i++;
    }
  }

  return Buffer.from(result, 'latin1');
}

function flattenMimeTree(node, result = []) {
  result.push(node);
  if (node.children) {
    for (const child of node.children) {
      flattenMimeTree(child, result);
    }
  }
  return result;
}

function formatMimeTree(node, indent = '') {
  let lines = [];
  const prefix = indent ? indent + '├── ' : '';

  let info = node.contentType;
  if (node.filename) info += ` (${node.filename})`;
  if (node.contentId) info += ` [cid:${node.contentId}]`;
  info += ` [${formatSize(node.size)}]`;
  info += ` [${node.contentTransferEncoding}]`;

  lines.push(prefix + info);

  if (node.children && node.children.length > 0) {
    for (let i = 0; i < node.children.length; i++) {
      const childIndent = indent + (i < node.children.length - 1 ? '│   ' : '    ');
      const childLines = formatMimeTree(node.children[i], childIndent);
      lines = lines.concat(childLines);
    }
  }

  return lines;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

module.exports = {
  parseMimeStructure,
  decodeContent,
  flattenMimeTree,
  formatMimeTree,
  formatSize,
  decodeQuotedPrintable,
  parseContentTypeAndDisposition,
  parseContentTypeHeader
};
