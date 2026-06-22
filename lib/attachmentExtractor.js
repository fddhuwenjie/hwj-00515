const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { decodeContent, flattenMimeTree, formatSize } = require('./mimeParser');
const { decodeHeaderValue } = require('./headerParser');

function extractAttachments(mimeTree, outputDir, options = {}) {
  const attachments = findAllAttachments(mimeTree);
  const results = [];
  const usedNames = new Set();

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  for (const attachment of attachments) {
    let filename = sanitizeFilename(attachment.filename || 'unnamed');
    filename = resolveFilenameConflict(filename, usedNames);
    usedNames.add(filename.toLowerCase());

    const filePath = path.join(outputDir, filename);
    const decoded = decodeContent(attachment.body, attachment.contentTransferEncoding, attachment.charset);
    const buffer = decoded.buffer;

    fs.writeFileSync(filePath, buffer);

    const sha256 = computeSHA256(buffer);

    results.push({
      filename,
      originalFilename: attachment.filename || 'unnamed',
      path: filePath,
      size: buffer.length,
      sizeFormatted: formatSize(buffer.length),
      contentType: attachment.contentType,
      contentId: attachment.contentId || null,
      contentDisposition: attachment.contentDisposition || null,
      sha256,
      isInline: attachment.contentDisposition === 'inline',
      isAttachment: attachment.contentDisposition === 'attachment' || !!attachment.filename,
      extension: getFileExtension(filename)
    });
  }

  return results;
}

function findAllAttachments(mimeTree) {
  const allParts = flattenMimeTree(mimeTree);
  const attachments = [];

  for (const part of allParts) {
    if (part.body === null) continue;

    const isAttachment = part.contentDisposition === 'attachment';
    const hasFilename = !!part.filename;
    const isInlineWithName = part.contentDisposition === 'inline' && part.filename;
    const isNonText = !part.contentType.toLowerCase().startsWith('text/') && !part.contentType.toLowerCase().startsWith('multipart/');

    if (isAttachment || hasFilename || isInlineWithName || (isNonText && part.contentId)) {
      attachments.push({
        ...part,
        filename: part.filename ? decodeHeaderValue(part.filename) : null
      });
    }
  }

  return attachments;
}

function sanitizeFilename(filename) {
  let name = filename;
  name = name.replace(/[\/\\<>:"|?*]/g, '_');
  name = name.replace(/[\x00-\x1f]/g, '');
  name = name.replace(/^\.+/, '');
  name = name.replace(/\.+$/, '');
  if (!name || name.length === 0) {
    name = 'unnamed';
  }
  if (name.length > 200) {
    const ext = path.extname(name);
    const base = path.basename(name, ext);
    name = base.substring(0, 195) + ext;
  }
  return name;
}

function resolveFilenameConflict(filename, usedNames) {
  const lowerName = filename.toLowerCase();
  if (!usedNames.has(lowerName)) {
    return filename;
  }

  const ext = path.extname(filename);
  const base = path.basename(filename, ext);

  let counter = 1;
  let newName;

  do {
    newName = `${base}_${counter}${ext}`;
    counter++;
  } while (usedNames.has(newName.toLowerCase()));

  return newName;
}

function computeSHA256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function getFileExtension(filename) {
  const ext = path.extname(filename).toLowerCase();
  return ext.startsWith('.') ? ext : `.${ext}`;
}

function listAttachments(mimeTree) {
  const attachments = findAllAttachments(mimeTree);
  return attachments.map(att => {
    const decoded = decodeContent(att.body, att.contentTransferEncoding, att.charset);
    const sha256 = computeSHA256(decoded.buffer);

    return {
      filename: att.filename || 'unnamed',
      size: decoded.buffer.length,
      sizeFormatted: formatSize(decoded.buffer.length),
      contentType: att.contentType,
      contentId: att.contentId || null,
      contentDisposition: att.contentDisposition || null,
      sha256,
      isInline: att.contentDisposition === 'inline',
      extension: getFileExtension(att.filename || 'unnamed')
    };
  });
}

module.exports = {
  extractAttachments,
  findAllAttachments,
  listAttachments,
  computeSHA256,
  sanitizeFilename,
  resolveFilenameConflict,
  getFileExtension
};
