/*  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.

 *  forward-decrypt v0.1.0-debug — auto-rebuild forwarded S/MIME-encrypted messages
 *  DEBUG BUILD: extensive logging for diagnostics
 */

const VERSION = (() => {
  try { return browser.runtime.getManifest().version; } catch { return "0.1.0"; }
})();

/* ---- Debug logging ---- */
let debugEnabled = false;

async function loadDebugFlag() {
  try {
    const { debug } = await browser.storage.local.get("debug");
    debugEnabled = !!debug;
  } catch (_) { debugEnabled = false; }
}

// Listen for storage changes (real-time toggle without restart)
browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.debug) {
    debugEnabled = !!changes.debug.newValue;
    log(`debug mode ${debugEnabled ? "ENABLED" : "DISABLED"}`);
  }
});

function log(...args)  { console.log(`[forward-decrypt v${VERSION}]`, ...args); }
function warn(...args) { console.warn(`[forward-decrypt v${VERSION}]`, ...args); }
function debug(...args) { if (debugEnabled) console.log(`[forward-decrypt v${VERSION} DEBUG]`, ...args); }

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/* ---- Tab bookkeeping ---- */
const processedTabIds   = new Set();
const pendingTabPollers = new Set();

/* Clean up on tab close */
browser.tabs.onRemoved.addListener(tabId => {
  debug(`tab ${tabId} closed, cleaning up`);
  processedTabIds.delete(tabId);
  pendingTabPollers.delete(tabId);
});

/* ======================================================================
 * waitForComposeDetails
 * Poll compose.getComposeDetails until a stable result is returned.
 * ====================================================================== */
async function waitForComposeDetails(tabId, { timeoutMs = 15000, pollMs = 200 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let attempts = 0;
  while (Date.now() < deadline) {
    attempts++;
    try {
      const d = await browser.compose.getComposeDetails(tabId);
      debug(`waitForComposeDetails tab ${tabId}: attempt ${attempts}, got details:`, d ? { type: d.type, isPlainText: d.isPlainText, relatedMessageId: d.relatedMessageId } : "null");
      if (d && typeof d.type === "string") return d;
    } catch (e) {
      debug(`waitForComposeDetails tab ${tabId}: attempt ${attempts}, error:`, e.message || e);
    }
    await sleep(pollMs);
  }
  warn(`waitForComposeDetails tab ${tabId}: timed out after ${attempts} attempts (${timeoutMs}ms)`);
  return null;
}

/* ======================================================================
 * isSmimeEncrypted
 * ====================================================================== */
async function isSmimeEncrypted(messageId) {
  debug(`isSmimeEncrypted(${messageId}): fetching raw...`);
  try {
    const raw = await browser.messages.getFull(messageId, { decrypt: false });
    const ct  = ((raw && raw.contentType) || "").toLowerCase();
    const hdr = ((raw && raw.headers && raw.headers["content-type"]) || []).join(" ").toLowerCase();
    const blob = ct + " " + hdr;
    const result = blob.includes("pkcs7-mime") && blob.includes("enveloped-data");
    debug(`isSmimeEncrypted(${messageId}):`, { contentType: raw?.contentType, result });
    return result;
  } catch (e) {
    warn(`isSmimeEncrypted(${messageId}) FAILED:`, e);
    return false;
  }
}

/* ======================================================================
 * canDecrypt
 * ====================================================================== */
async function canDecrypt(messageId) {
  debug(`canDecrypt(${messageId}): fetching full (decrypt=true)...`);
  try {
    const full = await browser.messages.getFull(messageId);
    const result = full && full.decryptionStatus === "success";
    debug(`canDecrypt(${messageId}): decryptionStatus=${full?.decryptionStatus}, result=${result}`);
    return result;
  } catch (e) {
    warn(`canDecrypt(${messageId}) FAILED:`, e);
    return false;
  }
}

/* ======================================================================
 * removeSmimeAttachments
 * ====================================================================== */
async function removeSmimeAttachments(tabId) {
  let removed = 0;
  try {
    const attachments = await browser.compose.listAttachments(tabId);
    debug(`removeSmimeAttachments(tab ${tabId}): found ${attachments.length} attachments:`, attachments.map(a => a.name));
    for (const att of attachments) {
      const n = (att.name || "").toLowerCase();
      if (n === "smime.p7m" || n === "smime.p7s" || n.endsWith(".p7m") || n.endsWith(".p7s")) {
        try {
          await browser.compose.removeAttachment(tabId, att.id);
          removed++;
          debug(`removeSmimeAttachments(tab ${tabId}): removed "${att.name}" (id ${att.id})`);
        } catch (e) { warn("removeAttachment failed", e); }
      }
    }
  } catch (e) { warn("listAttachments failed", e); }
  debug(`removeSmimeAttachments(tab ${tabId}): total removed=${removed}`);
  return removed;
}

/* ======================================================================
 * buildForwardHeader
 * ====================================================================== */
function buildForwardHeader(msg) {
  const subject = msg.subject || "";
  const author  = msg.author  || "";
  const date    = msg.date
    ? new Date(msg.date).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
    : "";
  const toList  = (msg.recipients || []).map(r => r || "").filter(Boolean).join(", ");
  const ccList  = (msg.ccList     || []).map(r => r || "").filter(Boolean).join(", ");

  const plainLines = [
    "-------- Forwarded Message --------",
    subject ? `Subject: ${subject}` : null,
    date    ? `Date: ${date}`       : null,
    author  ? `From: ${author}`     : null,
    toList  ? `To: ${toList}`       : null,
    ccList  ? `Cc: ${ccList}`       : null,
    "--------",
    "",
  ].filter(Boolean);

  const esc = s => String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

  const htmlLines = [
    '<table style="border-collapse:collapse;border:none;margin:4px 0">',
    subject ? `<tr><td style="padding:0 6px 0 0;font-weight:bold">Subject:</td><td>${esc(subject)}</td></tr>` : null,
    date    ? `<tr><td style="padding:0 6px 0 0;font-weight:bold">Date:</td><td>${esc(date)}</td></tr>`      : null,
    author  ? `<tr><td style="padding:0 6px 0 0;font-weight:bold">From:</td><td>${esc(author)}</td></tr>`    : null,
    toList  ? `<tr><td style="padding:0 6px 0 0;font-weight:bold">To:</td><td>${esc(toList)}</td></tr>`       : null,
    ccList  ? `<tr><td style="padding:0 6px 0 0;font-weight:bold">Cc:</td><td>${esc(ccList)}</td></tr>`       : null,
    "</table>",
  ].filter(Boolean);

  return {
    plain: plainLines.join("\n"),
    html:  htmlLines.join("\n"),
  };
}

/* ======================================================================
 * plainToHtml
 * ====================================================================== */
function plainToHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\r?\n/g, "<br>\n");
}

/* ======================================================================
 * rebuildForwardCompose
 * ====================================================================== */
async function rebuildForwardCompose(tabId, messageId, composeDetails) {
  log(`rebuilding forward for tab ${tabId}, messageId ${messageId}`);

  /* 1. Fetch original message header */
  debug(`[step 1] Fetching message header for messageId ${messageId}...`);
  let msgHeader = {};
  try {
    msgHeader = await browser.messages.get(messageId);
    debug(`[step 1] msgHeader:`, { subject: msgHeader?.subject, author: msgHeader?.author, date: msgHeader?.date });
  } catch (e) {
    warn(`[step 1] messages.get(${messageId}) failed:`, e);
  }
  const { plain: headerPlain, html: headerHtml } = buildForwardHeader(msgHeader);
  debug(`[step 1] headerPlain length=${headerPlain.length}, headerHtml length=${headerHtml.length}`);

  /* 2. Get decrypted inline text parts */
  debug(`[step 2] Fetching inline text parts for messageId ${messageId}...`);
  let plainPart = null, htmlPart = null;
  try {
    const parts = await browser.messages.listInlineTextParts(messageId);
    debug(`[step 2] listInlineTextParts returned ${parts.length} parts:`, parts.map(p => ({ contentType: p.contentType, contentLength: p.content?.length })));
    for (const p of parts) {
      if (p.contentType === "text/plain" && !plainPart) plainPart = p;
      if (p.contentType === "text/html"  && !htmlPart)  htmlPart  = p;
    }
  } catch (e) {
    warn(`[step 2] listInlineTextParts(${messageId}) FAILED:`, e);
  }
  debug(`[step 2] plainPart=${plainPart ? "yes (len=" + plainPart.content?.length + ")" : "no"}, htmlPart=${htmlPart ? "yes (len=" + htmlPart.content?.length + ")" : "no"}`);

  /* 3. Build body to match the compose's format */
  const isPlainText = composeDetails.isPlainText === true;
  debug(`[step 3] compose.isPlainText=${isPlainText}`);

  let newPlainBody = null, newHtmlBody = null;

  if (isPlainText) {
    let content = "";
    if (plainPart) {
      content = plainPart.content;
    } else if (htmlPart) {
      content = htmlPart.content
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
        .replace(/<br\s*\/?>/gi, "\n")
        .replace(/<\/p>/gi, "\n\n")
        .replace(/<[^>]+>/g, "")
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/&lt;/gi,  "<")
        .replace(/&gt;/gi,  ">")
        .replace(/&quot;/gi, '"')
        .replace(/\n{3,}/g, "\n\n")
        .trim();
    }
    newPlainBody = headerPlain + (content ? "\n\n" + content : "");
    debug(`[step 3] plain body built, length=${newPlainBody.length}`);
  } else {
    let content = "";
    if (htmlPart) {
      content = htmlPart.content;
    } else if (plainPart) {
      content = "<pre style=\"white-space:pre-wrap;word-wrap:break-word\">"
              + plainToHtml(plainPart.content)
              + "</pre>";
    }
    newHtmlBody = headerHtml + (content ? "<br><br>" + content : "");
    debug(`[step 3] html body built, length=${newHtmlBody.length}`);
  }

  /* 4. Remove any smime.p7m / .p7s attachments already present */
  debug(`[step 4] Removing smime attachments...`);
  const removedCount = await removeSmimeAttachments(tabId);
  debug(`[step 4] Removed ${removedCount} smime attachment(s)`);

  /* 5. Set body + force S/MIME encryption */
  const details = {};
  if (isPlainText) {
    details.plainTextBody = newPlainBody;
  } else {
    details.body = newHtmlBody;
  }
  details.selectedEncryptionTechnology = {
    name: "S/MIME",
    encryptBody: true,
    signMessage: true,
  };
  debug(`[step 5] setComposeDetails:`, { hasBody: !!details.body || !!details.plainTextBody, encryption: details.selectedEncryptionTechnology });
  try {
    await browser.compose.setComposeDetails(tabId, details);
    debug(`[step 5] setComposeDetails OK`);
  } catch (e) {
    warn(`[step 5] setComposeDetails FAILED:`, e);
  }

  /* 6. Add decrypted attachments */
  debug(`[step 6] Adding decrypted attachments...`);
  try {
    const attachments = await browser.messages.listAttachments(messageId);
    debug(`[step 6] Found ${attachments.length} decrypted attachments:`, attachments.map(a => ({ name: a.name, disposition: a.contentDisposition, contentType: a.contentType })));
    let addedCount = 0;
    for (const att of attachments) {
      if (att.contentDisposition === "inline" && att.contentType
          && att.contentType.startsWith("image/")) {
        debug(`[step 6] Skipping inline image "${att.name}"`);
        continue;
      }
      try {
        const file = await browser.messages.getAttachmentFile(messageId, att.partName);
        await browser.compose.addAttachment(tabId, { file, name: att.name || file.name });
        addedCount++;
        debug(`[step 6] Added attachment "${att.name}" (${file.name})`);
      } catch (e) {
        warn(`[step 6] addAttachment FAILED for "${att.name}":`, e);
      }
    }
    debug(`[step 6] Added ${addedCount} attachment(s)`);
  } catch (e) {
    warn(`[step 6] listAttachments(decrypted) FAILED:`, e);
  }

  log(`rebuild complete for tab ${tabId}`);
}

/* ======================================================================
 * processComposeTab
 * ====================================================================== */
async function processComposeTab(tabId) {
  debug(`processComposeTab(${tabId}): checking processedTabIds.has(${tabId}) = ${processedTabIds.has(tabId)}`);
  if (processedTabIds.has(tabId)) return;

  debug(`processComposeTab(${tabId}): waiting for compose details...`);
  const details = await waitForComposeDetails(tabId);
  if (!details) {
    debug(`processComposeTab(${tabId}): no details, aborting`);
    return;
  }

  debug(`processComposeTab(${tabId}): type="${details.type}", relatedMessageId=${details.relatedMessageId}, isPlainText=${details.isPlainText}`);

  /* Only act on forwards */
  if (details.type !== "forward") {
    debug(`processComposeTab(${tabId}): type is "${details.type}" (not "forward"), skipping`);
    return;
  }

  const relatedMessageId = details.relatedMessageId;
  if (!relatedMessageId) {
    debug(`processComposeTab(${tabId}): no relatedMessageId, skipping (forward-from-file?)`);
    return;
  }

  /* Must be S/MIME encrypted */
  debug(`processComposeTab(${tabId}): checking isSmimeEncrypted(${relatedMessageId})...`);
  if (!(await isSmimeEncrypted(relatedMessageId))) {
    debug(`processComposeTab(${tabId}): NOT smime encrypted, skipping`);
    return;
  }

  /* Must be decryptable */
  debug(`processComposeTab(${tabId}): checking canDecrypt(${relatedMessageId})...`);
  if (!(await canDecrypt(relatedMessageId))) {
    debug(`processComposeTab(${tabId}): CANNOT decrypt, skipping`);
    return;
  }

  processedTabIds.add(tabId);
  log(`processing forward compose tab ${tabId} for messageId ${relatedMessageId}`);

  try {
    await rebuildForwardCompose(tabId, relatedMessageId, details);
  } catch (e) {
    warn("rebuildForwardCompose failed", e);
  }

  /* Delayed sweep — smime.p7m may arrive asynchronously */
  setTimeout(async () => {
    debug(`delayed sweep (3s) for tab ${tabId}...`);
    const removed = await removeSmimeAttachments(tabId);
    if (removed) log(`delayed sweep removed ${removed} smime attachment(s) from tab ${tabId}`);
  }, 3000);

  /* Second sweep for very slow TB builds */
  setTimeout(async () => {
    debug(`second sweep (8s) for tab ${tabId}...`);
    const removed = await removeSmimeAttachments(tabId);
    if (removed) log(`second sweep removed ${removed} smime attachment(s) from tab ${tabId}`);
  }, 8000);
}

/* ======================================================================
 * Event listeners
 * ====================================================================== */

/* New compose window opened */
browser.tabs.onCreated.addListener(tab => {
  debug(`tabs.onCreated: tab.id=${tab?.id}, type=${tab?.type}, url=${tab?.url}`);
  if (tab && tab.type === "messageCompose") {
    debug(`tabs.onCreated: messageCompose detected, calling processComposeTab(${tab.id})`);
    processComposeTab(tab.id);
  }
});

/* Catch smime.p7m arriving late (after our initial pass) */
browser.compose.onAttachmentAdded.addListener((tab, attachment) => {
  debug(`onAttachmentAdded: tab=${tab?.id}, attachment.name=${attachment?.name}, attachment.id=${attachment?.id}`);
  if (!tab || !tab.id) return;
  const tabId = tab.id;
  if (!processedTabIds.has(tabId)) return;
  const n = (attachment && attachment.name || "").toLowerCase();
  if (n === "smime.p7m" || n === "smime.p7s" || n.endsWith(".p7m") || n.endsWith(".p7s")) {
    log(`caught late smime attachment "${attachment.name}" on tab ${tabId}, removing`);
    browser.compose.removeAttachment(tabId, attachment.id).catch(e => warn("late remove failed", e));
  }
});

/* ======================================================================
 * Startup
 * ====================================================================== */
(async () => {
  /* Load debug flag first */
  await loadDebugFlag();
  log("background loaded, listening for compose windows");
  if (debugEnabled) log("DEBUG MODE ACTIVE — verbose logging enabled");

  /* Process any already-open compose windows (e.g. after reload) */
  try {
    const tabs = await browser.tabs.query({ type: "messageCompose" });
    debug(`startup: found ${tabs.length} existing compose tab(s)`);
    for (const tab of tabs) {
      debug(`startup: processing existing compose tab ${tab.id}`);
      processComposeTab(tab.id);
    }
  } catch (e) {
    warn("startup tabs.query failed:", e);
  }
})();
