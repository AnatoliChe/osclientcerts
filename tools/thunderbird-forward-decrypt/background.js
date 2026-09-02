/*  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.

 *  forward-decrypt v0.1.0 — auto-rebuild forwarded S/MIME-encrypted messages
 */

const VERSION = (() => {
  try { return browser.runtime.getManifest().version; } catch { return "0.1.0"; }
})();

function log(...args)  { console.log(`[forward-decrypt v${VERSION}]`, ...args); }
function warn(...args) { console.warn(`[forward-decrypt v${VERSION}]`, ...args); }

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/* ---- Tab bookkeeping ---- */
const processedTabIds   = new Set();
const pendingTabPollers = new Set();   // tabIds currently being polled (avoid double-poll)

/* Clean up on tab close */
browser.tabs.onRemoved.addListener(tabId => {
  processedTabIds.delete(tabId);
  pendingTabPollers.delete(tabId);
});

/* ======================================================================
 * waitForComposeDetails
 * Poll compose.getComposeDetails until a stable result is returned.
 * Compose windows may not be ready immediately after tabs.onCreated.
 * Returns the details object or null on timeout.
 * ====================================================================== */
async function waitForComposeDetails(tabId, { timeoutMs = 15000, pollMs = 200 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const d = await browser.compose.getComposeDetails(tabId);
      if (d && typeof d.type === "string") return d;
    } catch (_) { /* not ready */ }
    await sleep(pollMs);
  }
  return null;
}

/* ======================================================================
 * isSmimeEncrypted
 * Return true if the given messageId refers to a S/MIME *encrypted*
 * (enveloped-data) message, as opposed to S/MIME signed or plain.
 * ====================================================================== */
async function isSmimeEncrypted(messageId) {
  try {
    const raw = await browser.messages.getFull(messageId, { decrypt: false });
    const ct  = ((raw && raw.contentType) || "").toLowerCase();
    const hdr = ((raw && raw.headers && raw.headers["content-type"]) || []).join(" ").toLowerCase();
    const blob = ct + " " + hdr;
    return blob.includes("pkcs7-mime") && blob.includes("enveloped-data");
  } catch (e) {
    warn("isSmimeEncrypted failed for", messageId, e);
    return false;
  }
}

/* ======================================================================
 * canDecrypt
 * Return true if the message can be successfully decrypted with the
 * user's available keys (decryptionStatus "success" on the root part).
 * ====================================================================== */
async function canDecrypt(messageId) {
  try {
    const full = await browser.messages.getFull(messageId);   // decrypt defaults to true
    return full && full.decryptionStatus === "success";
  } catch (e) {
    warn("canDecrypt failed for", messageId, e);
    return false;
  }
}

/* ======================================================================
 * removeSmimeAttachments
 * Remove any smime.p7m / smime.p7s attachments from a compose tab.
 * Returns the number removed.
 * ====================================================================== */
async function removeSmimeAttachments(tabId) {
  let removed = 0;
  try {
    const attachments = await browser.compose.listAttachments(tabId);
    for (const att of attachments) {
      const n = (att.name || "").toLowerCase();
      if (n === "smime.p7m" || n === "smime.p7s" || n.endsWith(".p7m") || n.endsWith(".p7s")) {
        try {
          await browser.compose.removeAttachment(tabId, att.id);
          removed++;
        } catch (e) { warn("removeAttachment failed", e); }
      }
    }
  } catch (e) { warn("listAttachments failed", e); }
  return removed;
}

/* ======================================================================
 * buildForwardHeader
 * Return { plain, html } with a simple "-------- Forwarded Message --------"
 * header block including Subject, Date, From, To.
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
 * Minimal plain-text to HTML conversion (escape + newlines to <br>).
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
 * The main rebuild routine: populate a forward compose window with the
 * decrypted content and re-enable S/MIME encryption.
 * ====================================================================== */
async function rebuildForwardCompose(tabId, messageId, composeDetails) {
  log(`rebuilding forward for tab ${tabId}, messageId ${messageId}`);

  /* 1. Fetch original message header for the forwarded-message block */
  let msgHeader = {};
  try { msgHeader = await browser.messages.get(messageId); } catch (_) { /* not fatal */ }
  const { plain: headerPlain, html: headerHtml } = buildForwardHeader(msgHeader);

  /* 2. Get decrypted inline text parts */
  let plainPart = null, htmlPart = null;
  try {
    const parts = await browser.messages.listInlineTextParts(messageId);
    for (const p of parts) {
      if (p.contentType === "text/plain" && !plainPart) plainPart = p;
      if (p.contentType === "text/html"  && !htmlPart)  htmlPart  = p;
    }
  } catch (e) { warn("listInlineTextParts failed", e); }

  /* 3. Build body to match the compose's format */
  const isPlainText = composeDetails.isPlainText === true;

  let newPlainBody = null, newHtmlBody = null;

  if (isPlainText) {
    let content = "";
    if (plainPart) {
      content = plainPart.content;
    } else if (htmlPart) {
      /* Rough HTML-to-plain: strip tags, collapse whitespace. Good enough for v0.1 */
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
  }

  /* 4. Remove any smime.p7m / .p7s attachments already present */
  await removeSmimeAttachments(tabId);

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
  try {
    await browser.compose.setComposeDetails(tabId, details);
  } catch (e) { warn("setComposeDetails (body) failed", e); }

  /* 6. Add decrypted attachments */
  try {
    const attachments = await browser.messages.listAttachments(messageId);
    for (const att of attachments) {
      /* Skip inline images — they're referenced via cid: in the HTML body and
       * re-adding them as regular attachments would lose the cid mapping. */
      if (att.contentDisposition === "inline" && att.contentType
          && att.contentType.startsWith("image/")) {
        continue;
      }
      try {
        const file = await browser.messages.getAttachmentFile(messageId, att.partName);
        await browser.compose.addAttachment(tabId, { file, name: att.name || file.name });
      } catch (e) {
        warn("addAttachment failed for", att.name, e);
      }
    }
  } catch (e) { warn("listAttachments (decrypted) failed", e); }

  log(`rebuild complete for tab ${tabId}`);
}

/* ======================================================================
 * processComposeTab
 * Main entry point: detect forward-of-encrypted, rebuild.
 * ====================================================================== */
async function processComposeTab(tabId) {
  if (processedTabIds.has(tabId)) return;

  const details = await waitForComposeDetails(tabId);
  if (!details) return;

  /* Only act on forwards */
  if (details.type !== "forward") return;

  const relatedMessageId = details.relatedMessageId;
  if (!relatedMessageId) return;   /* forward-from-file or unknown */

  /* Must be S/MIME encrypted */
  if (!(await isSmimeEncrypted(relatedMessageId))) return;

  /* Must be decryptable */
  if (!(await canDecrypt(relatedMessageId))) return;

  processedTabIds.add(tabId);
  log(`processing forward compose tab ${tabId} for messageId ${relatedMessageId}`);

  try {
    await rebuildForwardCompose(tabId, relatedMessageId, details);
  } catch (e) {
    warn("rebuildForwardCompose failed", e);
  }

  /* Delayed sweep — smime.p7m may arrive asynchronously */
  setTimeout(async () => {
    const removed = await removeSmimeAttachments(tabId);
    if (removed) log(`delayed sweep removed ${removed} smime attachment(s) from tab ${tabId}`);
  }, 3000);

  /* Second sweep for very slow TB builds */
  setTimeout(async () => {
    const removed = await removeSmimeAttachments(tabId);
    if (removed) log(`second sweep removed ${removed} smime attachment(s) from tab ${tabId}`);
  }, 8000);
}

/* ======================================================================
 * Event listeners
 * ====================================================================== */

/* New compose window opened */
browser.tabs.onCreated.addListener(tab => {
  if (tab && tab.type === "messageCompose") {
    processComposeTab(tab.id);
  }
});

/* Catch smime.p7m arriving late (after our initial pass) */
browser.compose.onAttachmentAdded.addListener((tab, attachment) => {
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
 * Startup: process any already-open compose windows (e.g. after reload)
 * ====================================================================== */
(async () => {
  try {
    const tabs = await browser.tabs.query({ type: "messageCompose" });
    for (const tab of tabs) {
      processComposeTab(tab.id);
    }
  } catch (e) { /* tabs.query may fail if tabs permission missing — non-fatal */ }
})();

log("background loaded, listening for compose windows");
