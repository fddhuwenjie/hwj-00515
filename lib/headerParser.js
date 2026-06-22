const { Buffer } = require('buffer');

function parseHeaders(rawContent) {
  const headerEnd = findHeaderEnd(rawContent);
  const rawHeaders = rawContent.substring(0, headerEnd);
  const bodyStart = headerEnd;

  const unfoldedHeaders = unfoldHeaders(rawHeaders);
  const headerLines = unfoldedHeaders.split(/\r?\n/).filter(line => line.length > 0);

  const headers = {};

  for (const line of headerLines) {
    const colonIndex = line.indexOf(':');
    if (colonIndex === -1) continue;

    const name = line.substring(0, colonIndex).trim().toLowerCase();
    const value = line.substring(colonIndex + 1).trim();

    if (!headers[name]) {
      headers[name] = [];
    }
    headers[name].push(decodeHeaderValue(value));
  }

  return {
    headers,
    bodyStart,
    get: (name) => headers[name.toLowerCase()] || [],
    getFirst: (name) => (headers[name.toLowerCase()] && headers[name.toLowerCase()][0]) || null
  };
}

function findHeaderEnd(content) {
  const patterns = ['\r\n\r\n', '\n\n'];
  let earliest = content.length;
  for (const pattern of patterns) {
    const index = content.indexOf(pattern);
    if (index !== -1 && index + pattern.length < earliest) {
      earliest = index + pattern.length;
    }
  }
  return earliest;
}

function unfoldHeaders(rawHeaders) {
  return rawHeaders.replace(/\r?\n[ \t]+/g, ' ');
}

function decodeHeaderValue(value) {
  if (!value) return value;

  const encodedWordRegex = /=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g;
  const parts = [];
  let lastIndex = 0;
  let match;
  let lastWasEncoded = false;

  while ((match = encodedWordRegex.exec(value)) !== null) {
    const between = value.substring(lastIndex, match.index);
    const charset = match[1].toUpperCase();
    const encoding = match[2].toUpperCase();
    const encodedText = match[3];

    if (lastWasEncoded && /^\s+$/.test(between)) {
      // 两个 encoded-word 之间只有空白，按 RFC 2047 忽略空白
    } else {
      parts.push(between);
    }

    parts.push(decodeEncodedWord(encodedText, encoding, charset));
    lastWasEncoded = true;
    lastIndex = match.index + match[0].length;
  }

  parts.push(value.substring(lastIndex));
  return parts.join('');
}

function decodeEncodedWord(encodedText, encoding, charset) {
  try {
    if (encoding === 'B') {
      const buf = Buffer.from(encodedText, 'base64');
      return iconvDecode(buf, charset);
    } else if (encoding === 'Q') {
      const decoded = decodeQuotedPrintableHeader(encodedText);
      return iconvDecode(decoded, charset);
    }
  } catch (e) {
    return encodedText;
  }
  return encodedText;
}

function decodeQuotedPrintableHeader(str) {
  let result = '';
  for (let i = 0; i < str.length; i++) {
    if (str[i] === '_') {
      result += ' ';
    } else if (str[i] === '=' && i + 2 < str.length) {
      const hex = str.substring(i + 1, i + 3);
      result += String.fromCharCode(parseInt(hex, 16));
      i += 2;
    } else {
      result += str[i];
    }
  }
  return Buffer.from(result, 'latin1');
}

function iconvDecode(buffer, charset) {
  const cs = (charset || '').toUpperCase();
  if (cs === 'UTF-8' || cs === 'UTF8') {
    return buffer.toString('utf8');
  }
  if (cs === 'ISO-8859-1' || cs === 'LATIN1' || cs === 'US-ASCII') {
    return buffer.toString('latin1');
  }
  try {
    const decoder = new TextDecoder(charset);
    return decoder.decode(buffer);
  } catch (e) {
    return buffer.toString('utf8');
  }
}

function parseAddressList(addressString) {
  if (!addressString) return [];

  const addresses = [];
  const parts = splitAddressList(addressString);

  for (const part of parts) {
    const addr = parseSingleAddress(part.trim());
    if (addr) addresses.push(addr);
  }

  return addresses;
}

function splitAddressList(str) {
  const result = [];
  let current = '';
  let inQuotes = false;
  let inAngle = false;

  for (let i = 0; i < str.length; i++) {
    const char = str[i];

    if (char === '"' && str[i - 1] !== '\\') {
      inQuotes = !inQuotes;
      current += char;
    } else if (char === '<' && !inQuotes) {
      inAngle = true;
      current += char;
    } else if (char === '>' && !inQuotes) {
      inAngle = false;
      current += char;
    } else if (char === ',' && !inQuotes && !inAngle) {
      result.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }

  if (current.trim()) {
    result.push(current.trim());
  }

  return result;
}

function parseSingleAddress(addrStr) {
  if (!addrStr) return null;

  const angleMatch = addrStr.match(/^(.+?)\s*<([^>]+)>\s*$/);
  if (angleMatch) {
    let name = angleMatch[1].trim();
    const email = angleMatch[2].trim().toLowerCase();

    if ((name.startsWith('"') && name.endsWith('"')) || (name.startsWith("'") && name.endsWith("'"))) {
      name = name.slice(1, -1);
    }

    return { name: name || '', email };
  }

  const email = addrStr.trim().toLowerCase();
  if (email.includes('@')) {
    return { name: '', email };
  }

  return null;
}

function parseDate(dateString) {
  if (!dateString) return null;
  const date = new Date(dateString);
  return isNaN(date.getTime()) ? null : date;
}

function extractEmailHeaders(headerData) {
  const from = parseAddressList(headerData.getFirst('from'));
  const to = parseAddressList(headerData.getFirst('to'));
  const cc = parseAddressList(headerData.getFirst('cc'));
  const bcc = parseAddressList(headerData.getFirst('bcc'));
  const replyTo = parseAddressList(headerData.getFirst('reply-to'));
  const subject = headerData.getFirst('subject') || '';
  const date = parseDate(headerData.getFirst('date'));
  const messageId = headerData.getFirst('message-id') || '';
  const mimeVersion = headerData.getFirst('mime-version') || '';

  return {
    from: from[0] || null,
    to,
    cc,
    bcc,
    replyTo,
    subject,
    date,
    dateString: headerData.getFirst('date') || '',
    messageId,
    mimeVersion,
    allHeaders: headerData.headers
  };
}

module.exports = {
  parseHeaders,
  decodeHeaderValue,
  parseAddressList,
  extractEmailHeaders,
  iconvDecode
};
