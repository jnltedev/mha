import { splitHeadersAndBody } from './headerParser.js';

const MSGREADER_CDN = 'https://cdn.jsdelivr.net/npm/@kenjiuno/msgreader@1.28.0/+esm';

export function parseEML(text) {
  return splitHeadersAndBody(text);
}

let msgReaderModulePromise = null;
function loadMsgReader() {
  if (!msgReaderModulePromise) {
    msgReaderModulePromise = import(MSGREADER_CDN);
  }
  return msgReaderModulePromise;
}

export async function parseMSG(arrayBuffer) {
  let MsgReader;
  try {
    const mod = await loadMsgReader();
    MsgReader = mod.default || mod.MSGReader || mod;
  } catch (e) {
    throw new Error('Could not load the .msg parser library (requires an internet connection). ' + e.message);
  }

  const reader = new MsgReader(new Uint8Array(arrayBuffer));
  const fileData = reader.getFileData();

  if (fileData.error) {
    throw new Error('Failed to parse .msg file: ' + fileData.error);
  }

  let headerBlock = fileData.headers && fileData.headers.trim() ? fileData.headers : null;
  let note = null;

  if (!headerBlock) {
    headerBlock = reconstructHeaders(fileData);
    note =
      'This .msg file does not contain the original raw transport headers (PR_TRANSPORT_MESSAGE_HEADERS was empty — common for locally-composed drafts). Only limited metadata could be reconstructed, so SPF / DKIM / DMARC cannot be evaluated.';
  }

  const body = typeof fileData.body === 'string' ? fileData.body : null;

  return { headerBlock, body, note, raw: fileData };
}

function reconstructHeaders(fileData) {
  const lines = [];
  if (fileData.subject) lines.push(`Subject: ${fileData.subject}`);
  const from = fileData.senderEmail
    ? `${fileData.senderName || ''} <${fileData.senderEmail}>`.trim()
    : fileData.senderName || '';
  if (from) lines.push(`From: ${from}`);
  if (Array.isArray(fileData.recipients) && fileData.recipients.length) {
    const to = fileData.recipients
      .filter((r) => !r.recipType || r.recipType === 'to')
      .map((r) => (r.email ? `${r.name || ''} <${r.email}>`.trim() : r.name))
      .filter(Boolean)
      .join(', ');
    if (to) lines.push(`To: ${to}`);
  }
  const date = fileData.clientSubmitTime || fileData.messageDeliveryTime || fileData.creationTime;
  if (date) lines.push(`Date: ${date}`);
  return lines.join('\n');
}
