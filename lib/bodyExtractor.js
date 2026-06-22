const { decodeContent, flattenMimeTree } = require('./mimeParser');
const { decodeHeaderValue } = require('./headerParser');

function extractBodies(mimeTree) {
  const allParts = flattenMimeTree(mimeTree);
  const bodies = {
    text: null,
    html: null,
    parts: []
  };

  for (const part of allParts) {
    if (part.body === null || part.body === undefined) continue;

    const contentType = part.contentType.toLowerCase();

    if (contentType.startsWith('text/plain') && !isAttachment(part)) {
      if (!bodies.text) {
        const decoded = decodeContent(part.body, part.contentTransferEncoding, part.charset);
        bodies.text = decoded.text;
        bodies.parts.push({
          type: 'text/plain',
          content: decoded.text,
          charset: part.charset,
          encoding: part.contentTransferEncoding
        });
      }
    }

    if (contentType.startsWith('text/html') && !isAttachment(part)) {
      if (!bodies.html) {
        const decoded = decodeContent(part.body, part.contentTransferEncoding, part.charset);
        bodies.html = decoded.text;
        bodies.parts.push({
          type: 'text/html',
          content: decoded.text,
          charset: part.charset,
          encoding: part.contentTransferEncoding
        });
      }
    }
  }

  return bodies;
}

function isAttachment(part) {
  if (part.contentDisposition && part.contentDisposition.toLowerCase() === 'attachment') {
    return true;
  }
  if (part.filename) {
    return true;
  }
  return false;
}

function htmlToPlainText(html) {
  if (!html) return '';

  let text = html;

  text = text.replace(/<head[\s\S]*?<\/head>/gi, '');
  text = text.replace(/<script[\s\S]*?<\/script>/gi, '');
  text = text.replace(/<style[\s\S]*?<\/style>/gi, '');

  text = text.replace(/<br\s*\/?>/gi, '\n');
  text = text.replace(/<\/p>/gi, '\n\n');
  text = text.replace(/<\/div>/gi, '\n');
  text = text.replace(/<\/li>/gi, '\n');
  text = text.replace(/<\/tr>/gi, '\n');
  text = text.replace(/<\/h[1-6]>/gi, '\n\n');

  text = text.replace(/<[^>]+>/g, '');

  text = htmlDecode(text);

  text = text.replace(/\n{3,}/g, '\n\n');
  text = text.replace(/[ \t]+/g, ' ');
  text = text.replace(/^[ \t]+/gm, '');

  return text.trim();
}

function htmlDecode(str) {
  const entities = {
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&quot;': '"',
    '&apos;': "'",
    '&nbsp;': ' ',
    '&copy;': '©',
    '&reg;': '®',
    '&trade;': '™',
    '&euro;': '€',
    '&pound;': '£',
    '&yen;': '¥',
    '&middot;': '·',
    '&mdash;': '—',
    '&ndash;': '–',
    '&hellip;': '…',
    '&lsquo;': '‘',
    '&rsquo;': '’',
    '&ldquo;': '"',
    '&rdquo;': '"'
  };

  let result = str;

  for (const [entity, char] of Object.entries(entities)) {
    result = result.replace(new RegExp(entity, 'gi'), char);
  }

  result = result.replace(/&#(\d+);/g, (match, num) => {
    return String.fromCharCode(parseInt(num, 10));
  });

  result = result.replace(/&#x([0-9a-fA-F]+);/g, (match, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  return result;
}

function extractInlineImages(mimeTree) {
  const allParts = flattenMimeTree(mimeTree);
  const images = [];

  for (const part of allParts) {
    if (part.body === null) continue;

    const isInline = part.contentDisposition === 'inline';
    const hasCid = !!part.contentId;
    const isImage = part.contentType.toLowerCase().startsWith('image/');

    if ((isInline || hasCid) && isImage) {
      const decoded = decodeContent(part.body, part.contentTransferEncoding, part.charset);
      images.push({
        cid: part.contentId,
        contentType: part.contentType,
        filename: part.filename || (part.contentId ? part.contentId : ''),
        size: decoded.buffer.length,
        contentId: part.contentId,
        buffer: decoded.buffer
      });
    }
  }

  return images;
}

function extractExternalImageUrls(html) {
  if (!html) return [];

  const urls = [];
  const imgRegex = /<img[^>]+src=["']([^"']+)["'][^>]*>/gi;
  let match;

  while ((match = imgRegex.exec(html)) !== null) {
    const src = match[1];
    if (src.startsWith('http://') || src.startsWith('https://')) {
      if (!urls.includes(src)) {
        urls.push(src);
      }
    }
  }

  return urls;
}

function getBodySummary(text, maxLength = 200) {
  if (!text) return '';
  const cleaned = text.replace(/\s+/g, ' ').trim();
  if (cleaned.length <= maxLength) return cleaned;
  return cleaned.substring(0, maxLength) + '...';
}

module.exports = {
  extractBodies,
  htmlToPlainText,
  extractInlineImages,
  extractExternalImageUrls,
  getBodySummary,
  isAttachment
};
