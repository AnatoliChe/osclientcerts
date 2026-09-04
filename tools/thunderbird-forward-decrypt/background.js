/*  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.

 *  forward-decrypt v0.1.2-debug — auto-rebuild forwarded S/MIME-encrypted messages
 *  DEBUG BUILD: extensive logging for diagnostics
 */

const VERSION = (() => {
  try { return browser.runtime.getManifest().version; } catch { return "0.1.0"; }
})();

/* ---- Debug logging ---- */
let debugEnabled = false;

async function loadDebugFlag() {
  try {
    const { debug } = await browser.storage.local.get(["debug"]);
    debugEnabled = !!debug;
  } catch (_) { debugEnabled = false; }
}

// Listen for storage changes (real-time toggle without restart)
browser.storage.onChanged.addListener(async (changes, area) => {
  if (area === "local") {
    if (changes.debug) {
      debugEnabled = !!changes.debug.newValue;
      log(`debug mode ${debugEnabled ? "ENABLED" : "DISABLED"}`);
    }
  }
});

function log(...args)  { console.log(`[forward-decrypt v${VERSION}]`, ...args); }
function warn(...args) { console.warn(`[forward-decrypt v${VERSION}]`, ...args); }
function debug(...args) { if (debugEnabled) console.log(`[forward-decrypt v${VERSION} DEBUG]`, ...args); }

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/* ---- Tab bookkeeping ---- */
const processedTabIds   = new Set();
const pendingTabPollers = new Set();
const closedTabIds      = new Set();
const removingAttachmentKeys = new Set();
/* Tabs opened by THIS plugin (e.g. the reply window rebuilt for an embedded
 * container) — these must NEVER be re-processed, otherwise the plugin would
 * cascade and spawn unbounded compose windows. */
const selfOpenedTabIds  = new Set();

/* Clean up on tab close */
browser.tabs.onRemoved.addListener(tabId => {
  debug(`tab ${tabId} closed, cleaning up`);
  processedTabIds.delete(tabId);
  pendingTabPollers.delete(tabId);
  selfOpenedTabIds.delete(tabId);
  closedTabIds.add(tabId);
});

/* ======================================================================
 * waitForComposeDetails
 * Poll compose.getComposeDetails until a stable result is returned.
 * ====================================================================== */
async function waitForComposeDetails(tabId, { timeoutMs = 15000, pollMs = 200 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let attempts = 0;
  while (Date.now() < deadline) {
    if (closedTabIds.has(tabId)) {
      debug(`waitForComposeDetails tab ${tabId}: tab closed, stopping`);
      return null;
    }
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
 * walkParts
 * Recursively walk a MessagePart tree, invoking cb(part, path) for every
 * part (root + all sub-parts). `path` is a MIME part-path like "1" or "1.2"
 * (empty for the root). Handles embedded message/rfc822 containers.
 * ====================================================================== */
function walkParts(part, cb, path = "") {
  if (!part) return;
  cb(part, path);
  const subs = part.parts || [];
  for (let i = 0; i < subs.length; i++) {
    walkParts(subs[i], cb, path ? `${path}.${i + 1}` : `${i + 1}`);
  }
}

/* ======================================================================
 * partLooksSmimeEncrypted
 * Return true if a single part advertises S/MIME encapsulation
 * (pkcs7-mime + enveloped-data), checked on both contentType and headers.
 * ====================================================================== */
function partLooksSmimeEncrypted(part) {
  if (!part) return false;
  const ct  = ((part.contentType) || "").toLowerCase();
  const hdr = ((part.headers && part.headers["content-type"]) || []).join(" ").toLowerCase();
  const blob = ct + " " + hdr;
  return blob.includes("pkcs7-mime") && blob.includes("enveloped-data");
}

/* ======================================================================
 * dumpPartTree
 * When debug is enabled, print the full structure of a MessagePart tree
 * (partName, contentType, decryptionStatus, name, disposition, body length,
 * child count) so diagnostics show exactly where S/MIME / decrypted
 * content lives, including inside embedded message/rfc822 containers.
 * ====================================================================== */
function dumpPartTree(label, part, messageId) {
  walkParts(part, (p, pathName) => {
    debug(`[tree:${label}] ${messageId} part ${pathName || "(root)"}:`,
      { contentType: p.contentType,
        decryptionStatus: p.decryptionStatus,
        name: p.name,
        disposition: p.contentDisposition,
        partName: p.partName,
        bodyLen: (p.body != null) ? p.body.length : undefined,
        subParts: (p.parts || []).length });
  });
}

/* ======================================================================
 * isSmimeEncrypted
 * Recursively determine whether a message (or any embedded sub-message /
 * message/rfc822 container) contains a S/MIME encrypted (enveloped-data)
 * part. Checks every part in the tree, not just the root.
 * ====================================================================== */
async function isSmimeEncrypted(messageId) {
  debug(`isSmimeEncrypted(${messageId}): fetching raw...`);
  try {
    const raw = await browser.messages.getFull(messageId, { decrypt: false });
    dumpPartTree("raw(decrypt:false)", raw, messageId);
    let found = false;
    walkParts(raw, (p) => {
      if (partLooksSmimeEncrypted(p)) found = true;
    });
    debug(`isSmimeEncrypted(${messageId}): recursive result=${found}`);
    return found;
  } catch (e) {
    warn(`isSmimeEncrypted(${messageId}) FAILED:`, e);
    return false;
  }
}

/* ======================================================================
 * getRootContentType
 * Return the top-level Content-Type of a message (raw, undecrypted), or
 * null on error. Used to distinguish an embedded message/rfc822 container
 * from a normal top-level S/MIME message.
 * ====================================================================== */
async function getRootContentType(messageId) {
  try {
    const raw = await browser.messages.getFull(messageId, { decrypt: false });
    return (raw && raw.contentType) || null;
  } catch (e) {
    warn(`getRootContentType(${messageId}) FAILED:`, e);
    return null;
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

/* Replace a leading "Re:" with "Fwd:" so a reply rebuilt from an embedded
 * message/rfc822 container reads as a forward. Only the first prefix is
 * retitled, so nested "Re: Re: X" becomes "Fwd: Re: X". Returns "" when the
 * input has no leading "Re:" (so callers can skip the write). */
function retitleReplyToForward(subject) {
  const s = (subject || "").trim();
  const m = /^([\s]*)(re:\s*)(.*)$/i.exec(s);
  if (!m) return "";
  const rest = m[3] ? m[3].trim() : "";
  return `${m[1]}Fwd:${rest ? " " + rest : ""}`.trim();
}

/* ======================================================================
 * dumpAttachmentSources
 * Diagnostic probe for the embedded message/rfc822 S/MIME container: report
 * where the decrypted body + standalone attachment bytes actually live. We
 * probe four candidate sources:
 *   1. replyWindow  - getComposeDetails(tabId).attachments (what TB put in the
 *                     materialized reply CompFields)
 *   2. apiList      - browser.messages.listAttachments(messageId)
 *   3. decrypted    - getFull(messageId) with decrypt:true — dump the full part
 *                     tree AND the leaf parts that look like real attachments,
 *                     then try getAttachmentFile on a nested part (Path A test)
 *   4. inlineParts  - browser.messages.listInlineTextParts(messageId)
 * Debug-only. Decides whether the attachment re-add in handleExperimentReplyTab
 * can source bytes from the messages API (Path A) or needs a new privileged
 * ForwardIntercept extraction (Path B).
 * ====================================================================== */
async function fetchFirstDecryptedAttachment(messageId, part, path = "") {
  if (!part) return;
  const fileName = p => (p.name || p.partName || "").toString().toLowerCase();
  /* Try this node if it looks like a real (non-envelope, non-inline) part. */
  const n = fileName(part);
  const disp = part.contentDisposition;
  if (!(n.endsWith(".p7m") || n.endsWith(".p7s")) && disp !== "inline") {
    const partName = part.partName || path || "";
    if (partName) {
      try {
        const f = await browser.messages.getAttachmentFile(messageId, partName);
        debug(`[probe] getAttachmentFile OK part=${partName} name=${part.name} ct=${part.contentType} size=${f && f.size}`);
      } catch (e) {
        debug(`[probe] getAttachmentFile FAIL part=${partName} name=${part.name}:`, e.message);
      }
    }
  }
  const subs = part.parts || [];
  for (let i = 0; i < subs.length; i++) {
    await fetchFirstDecryptedAttachment(messageId, subs[i], path ? `${path}.${i + 1}` : `${i + 1}`);
  }
}

async function dumpAttachmentSources(tabId, messageId) {
  const out = {};

  try {
    const d = await browser.compose.getComposeDetails(tabId);
    out.replyWindow = (d && d.attachments || []).map(a =>
      `${a.name}(${a.size},${a.type || ''},${a.partName || ''})`);
  } catch (e) {
    out.replyWindow = "ERR " + e.message;
  }

  /* The outgoing attachment list of the reply window itself — what Thunderbird
   * would actually send. If a real standalone file shows up here, it forwards. */
  try {
    const list = await browser.compose.listAttachments(tabId);
    out.replyOutgoing = list.map(a =>
      `${a.name}(${a.size},${a.type || ''},disp=${a.contentDisposition || ''})`);
  } catch (e) {
    out.replyOutgoing = "ERR " + e.message;
  }

  try {
    const list = await browser.messages.listAttachments(messageId);
    out.apiList = list.map(a => ({
      name: a.name,
      ct: a.contentType,
      disp: a.contentDisposition,
      part: a.partName,
    }));
  } catch (e) {
    out.apiList = "ERR " + e.message;
  }

  /* The key Path-A test: does getFull(decrypt:true) surface the decrypted
   * body + attachment parts (as nested sub-parts)? canDecrypt reported
   * decryptionStatus=success, so the engine CAN decrypt — the question is
   * whether the resulting tree exposes the inner parts via the WE API. */
  try {
    const full = await browser.messages.getFull(messageId);
    debug(`[probe] getFull(decrypt:true) root:`, full && {
      contentType: full.contentType,
      decryptionStatus: full.decryptionStatus,
      subParts: (full.parts || []).length,
    });
    dumpPartTree("full(decrypt:true)", full, messageId);
    await fetchFirstDecryptedAttachment(messageId, full);
  } catch (e) {
    warn("[probe] getFull(decrypt:true) FAILED:", e);
  }

  try {
    const parts = await browser.messages.listInlineTextParts(messageId);
    debug("[probe] listInlineTextParts count:", parts.length,
      parts.map(p => `${p.contentType}(${p.content ? p.content.length : 0})`));
  } catch (e) {
    debug("[probe] listInlineTextParts FAILED:", e.message);
  }

  debug("[probe] summary =>", out);
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

  /* 2. Get the decrypted inline text parts.
   *    We use messages.listInlineTextParts (and listAttachments in step 6)
   *    rather than walking the raw getFull() tree because these APIs are
   *    decryption-aware: "If the message is encrypted, the inline text parts
   *    of the decrypted message are listed." This also handles the case where
   *    the S/MIME envelope is nested one level inside a message/rfc822
   *    embedded container, which getFull() does not surface. */
  debug(`[step 2] Fetching decrypted inline text parts for messageId ${messageId}...`);
  let plainPart = null, htmlPart = null;
  let decryptedTree = null;
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

  /* 6. Add the decrypted attachments via listAttachments (decryption-aware).
   *    We explicitly skip any .p7m/.p7s entries: the S/MIME envelope blob
   *    must never be re-attached (it is a wrapper, not a real attachment,
   *    and the onAttachmentAdded guard removes it anyway). */
  debug(`[step 6] Fetching decrypted attachments for messageId ${messageId}...`);
  let addedCount = 0;
  try {
    const attachments = await browser.messages.listAttachments(messageId);
    debug(`[step 6] listAttachments returned ${attachments.length} attachment(s):`, attachments.map(a => ({ name: a.name, disposition: a.contentDisposition, contentType: a.contentType })));
    for (const att of attachments) {
      const n = (att.name || "").toLowerCase();
      if (n === "smime.p7m" || n === "smime.p7s" || n.endsWith(".p7m") || n.endsWith(".p7s")) {
        debug(`[step 6] Skipping S/MIME envelope attachment "${att.name}"`);
        continue;
      }
      const isInlineImage = att.contentDisposition === "inline" && att.contentType
          && att.contentType.startsWith("image/");
      if (isInlineImage) {
        debug(`[step 6] Skipping inline image "${att.name}"`);
        continue;
      }
      try {
        const file = await browser.messages.getAttachmentFile(messageId, att.partName);
        await browser.compose.addAttachment(tabId, { file, name: att.name || file.name });
        addedCount++;
        debug(`[step 6] Added attachment "${att.name}" (${file.name}) part=${att.partName}`);
      } catch (e) {
        warn(`[step 6] addAttachment FAILED for "${att.name}" (part ${att.partName}):`, e);
      }
    }
  } catch (e) {
    warn(`[step 6] listAttachments(decrypted) FAILED:`, e);
  }
  debug(`[step 6] Added ${addedCount} attachment(s)`);

  log(`rebuild complete for tab ${tabId}`);
}

/* ======================================================================
 * handleEmbeddedForward
 * Final logic for a message/rfc822 container that is an S/MIME forward.
 *
 * The decrypted content (text body, inline images, and real file attachments)
 * is NOT reachable through the messages API (getFull / listInlineTextParts /
 * listAttachments return only the smime envelope for such nested containers),
 * and there is no privileged Experiment in Manifest v3. However, when TB opens
 * a *reply* compose window on the container it materializes the FULL decrypted
 * content — including inline images and file attachments — because it decrypts
 * on the fly for display.
 *
 * Therefore, for an embedded container we intercept the user's forward and
 * instead:
 *   1. open a reply window on the container,
 *   2. wait for the decrypted body AND attachments to materialize,
 *   3. clear the recipient fields (To/Cc/Bcc), turning the reply into a
 *      de-facto "forward" that will NOT be sent back to the original sender,
 *   4. close the original (empty) forward window,
 *   5. leave the reply window open for the user to add new recipients + send.
 *
 * This preserves text, inline images, and attachments without any privileged
 * API. The reply keeps its "Re:" subject, which is acceptable for a forward.
 * ====================================================================== */
async function handleEmbeddedForward(tabId, messageId, composeDetails) {
  log(`embedded forward (messageId ${messageId}): rebuilding as reply with cleared recipients (fwd tab ${tabId})`);

  let replyTabId = null;
  try {
    /* Open a reply on the container — this is the only way to materialize the
     * full decrypted content (body + inline images + attachments). */
    const replyTab = await browser.compose.beginReply(messageId, "replyToSender");
    if (!replyTab || !replyTab.id) {
      warn("[embedded] beginReply returned no reply tab — aborting");
      return false;
    }
    replyTabId = replyTab.id;
    selfOpenedTabIds.add(replyTabId);   /* never re-process our own window */

    /* Wait for compose details (body may load asynchronously). */
    const d = await waitForComposeDetails(replyTabId);
    if (!d) {
      warn("[embedded] could not read reply compose details — aborting");
      return;
    }
    const bodyLen = (d.body ? d.body.length : 0) || (d.plainTextBody ? d.plainTextBody.length : 0);
    debug(`[embedded] reply window ready: bodyLen=${bodyLen}`);

    /* Give real file attachments / inline images time to materialize, exactly
     * as the smime envelope can arrive late. Then clear every recipient field
     * so the reply is not sent back to the original sender and effectively
     * becomes a forward. */
    await sleep(3000);
    const replyDetails = await waitForComposeDetails(replyTabId);

    const clear = {
      to: [],
      cc: [],
      bcc: [],
    };
    /* replyToRecipients not part of setComposeDetails in MV3 — omit it. */
    try {
      await browser.compose.setComposeDetails(replyTabId, clear);
      log(`[embedded] recipients cleared on reply window ${replyTabId}`);
    } catch (e2) {
      warn("[embedded] clearing recipients FAILED:", e2);
    }

    /* The reply rebuilt a forward, so retitle the subject: replace the leading
     * "Re:" with "Fwd:" so it reads as a forward, not a reply. Handles nested
     * "Re: Re: ..." by only touching the first prefix (=> "Fwd: Re: ..."). */
    try {
      const cur = await waitForComposeDetails(replyTabId);
      const subject = (cur && cur.subject) || "";
      const fwdSubject = retitleReplyToForward(subject);
      if (fwdSubject) {
        await browser.compose.setComposeDetails(replyTabId, { subject: fwdSubject });
        log(`[embedded] subject retitled: "${subject}" -> "${fwdSubject}"`);
      } else {
        debug(`[embedded] subject unchanged (no "Re:" prefix): "${subject}"`);
      }
    } catch (e4) {
      warn("[embedded] retitling subject FAILED:", e4);
    }

    /* Optionally surface the attachment list for the debug log. */
    debug(`[embedded] reply attachments =>`,
      (replyDetails && (replyDetails.attachments || []) || []).map(a =>
        `${a.name}(${a.size},${(a.type || "")})`));

    /* Close the original empty forward window — its content would be broken
     * (only the smime envelope). The reply window now stands in for it. */
    try {
      await browser.tabs.remove(tabId);
      log(`[embedded] closed original forward window ${tabId}; user operations now target reply window ${replyTabId}`);
    } catch (e3) {
      warn("[embedded] could not close original forward window:", e3);
    }

    log(`[embedded] DONE: reply-window-forward ${replyTabId} ready for new recipients`);
    return true;
  } catch (e) {
    warn("[embedded] handleEmbeddedForward FAILED:", e);
    /* On failure, keep the reply window open so the user has something usable
     * rather than the broken empty forward. */
    return false;
  }
}

/* ======================================================================
 * handleExperimentReplyTab
 * When the ForwardIntercept experiment redirects an embedded message/rfc822
 * forward into a reply window, that window opens with type "reply". Unlike
 * handleEmbeddedForward we do NOT open a new reply (one is already open);
 * we just clear the recipient fields (To/Cc/Bcc) and retitle the "Re:" subject
 * to "Fwd:", turning the reply into a de-facto forward. Runs after the reply
 * body/attachments have materialized.
 * ====================================================================== */
async function handleExperimentReplyTab(tabId, messageId) {
  log(`[experiment] reply window (tab ${tabId}) from redirected forward on messageId ${messageId}: clearing recipients + retitling`);

  /* Clear the recipient fields and retitle the subject ASAP so the window does
   * NOT visibly show the original recipients / "Re:" first (TB fills the reply
   * recipients from the message header at open time, so we must clear right
   * after the tab is created). No fixed sleep here — poll the compose window
   * until it accepts the write (it becomes writable within a few hundred ms). */
  const d = await waitForComposeDetails(tabId);
  if (!d) {
    warn(`[experiment] reply window ${tabId}: could not read compose details`);
    return false;
  }

  const clearRecipients = async () => {
    for (let tries = 0; tries < 15; tries++) {
      try {
        await browser.compose.setComposeDetails(tabId, { to: [], cc: [], bcc: [] });
        log(`[experiment] recipients cleared on reply window ${tabId}`);
        return true;
      } catch (e2) {
        /* Window not ready yet — wait briefly and retry. */
        await sleep(200);
      }
    }
    warn("[experiment] clearing recipients FAILED (still not writable)");
    return false;
  };

  const retitleSubject = async () => {
    try {
      const cur = await waitForComposeDetails(tabId);
      const subject = (cur && cur.subject) || "";
      const fwdSubject = retitleReplyToForward(subject);
      if (fwdSubject) {
        await browser.compose.setComposeDetails(tabId, { subject: fwdSubject });
        log(`[experiment] subject retitled: "${subject}" -> "${fwdSubject}"`);
      } else {
        debug(`[experiment] subject unchanged (no "Re:" prefix): "${subject}"`);
      }
    } catch (e4) {
      warn("[experiment] retitling subject FAILED:", e4);
    }
  };

  await Promise.all([clearRecipients(), retitleSubject()]);

  /* Wait for Thunderbird's actual ComposeBodyReady notification instead of a
   * fixed delay. Fast machines continue immediately; slow machines wait for
   * quote construction to finish. A closed window cancels the operation. */
  let composeReady = "unavailable";
  try {
    composeReady = await browser.ForwardIntercept.waitForRedirectedComposeReady(8000);
  } catch (e) {
    warn(`[experiment] compose readiness wait failed: ${e.message || e}`);
  }
  log(`[experiment] redirected compose readiness: ${composeReady}`);
  if (composeReady === "closed") {
    log(`[experiment] reply window ${tabId} closed before body was ready; stopping`);
    return false;
  }
  if (closedTabIds.has(tabId)) return false;
  if (composeReady !== "ready") {
    warn(`[experiment] no ComposeBodyReady signal (${composeReady}); continuing with persistence retries`);
  }

  /* 0.3.x diagnostic: where do the decrypted attachments live? Debug-only. */
  if (debugEnabled) {
    try { await dumpAttachmentSources(tabId, messageId); } catch (e) { warn("[probe] failed:", e); }
    /* Parent-scope read of Thunderbird's real CompFields attachment model. */
    try {
      const rows = await browser.ForwardIntercept.getComposeAttachments(tabId);
      debug("[probe] parent gMsgComposeFields.attachments =>", rows);
    } catch (e) {
      debug("[probe] getComposeAttachments FAILED:", e.message);
    }
  }

  /* v0.3.3 Path B: Thunderbird's CompFields carry NO standalone file for an
   * embedded message/rfc822 S/MIME container (that's why the reply shows the
   * body but drops TEst.txt). So we decrypt + extract via the parent-scope
   * gloda engine and RE-ATTACH the standalone files to this compose window. */
  try {
    let fwdUri = null;
    try {
      fwdUri = await browser.ForwardIntercept.getLastForwardUri();
      debug(`[experiment] lastForwardUri => ${fwdUri}`);
    } catch (e3) {
      warn("[experiment] getLastForwardUri FAILED:", e3);
    }
    if (fwdUri) {
      const { rows, log: notes } =
        await browser.ForwardIntercept.extractDecryptedAttachments(fwdUri);
      if (closedTabIds.has(tabId)) {
        log(`[experiment] reply window ${tabId} closed during attachment extraction; stopping`);
        return false;
      }
      debug(`[experiment] extractDecryptedAttachments ${fwdUri} =>`, notes, rows);
      let added = 0;
      for (const att of rows) {
        const n = (att.name || "").toLowerCase();
        if (n.endsWith(".p7m") || n.endsWith(".p7s")) continue;
        if (att.contentType && att.contentType.startsWith("image/")) continue;
        try {
          const bytes = Uint8Array.from(atob(att.dataBase64), c => c.charCodeAt(0));
          const name = att.name || "attachment";
          let persistent = false;
          for (let attempt = 1; attempt <= 3; attempt++) {
            const current = await browser.compose.listAttachments(tabId);
            const found = current.some(item => item.name === name);
            debug(`[experiment] attachment persistence check ${attempt} for "${name}": found=${found}; current=${current.map(item => item.name).join(",")}`);
            if (found) {
              await sleep(500);
              const stable = await browser.compose.listAttachments(tabId);
              if (stable.some(item => item.name === name)) {
                persistent = true;
                break;
              }
              warn(`[experiment] attachment "${name}" disappeared after add; retrying`);
            }
            const file = new File([bytes], name, {
              type: att.contentType || "application/octet-stream",
            });
            await browser.compose.addAttachment(tabId, { file, name });
            log(`[experiment] add attempt ${attempt} for "${name}" (${bytes.length} bytes) on window ${tabId}`);
            await sleep(250);
          }
          if (persistent) {
            added++;
            log(`[experiment] re-attached and verified "${name}" (${bytes.length} bytes) on window ${tabId}`);
          } else {
            warn(`[experiment] attachment "${name}" was not persistent after retries`);
          }
        } catch (e5) {
          warn(`[experiment] addAttachment FAILED for "${att.name}":`, e5);
        }
      }
      log(`[experiment] re-attached ${added} standalone attachment(s) to window ${tabId}`);
    } else {
      debug("[experiment] no lastForwardUri captured — skipping Path B re-attach");
    }
  } catch (e6) {
    warn("[experiment] Path B extract/re-attach FAILED:", e6);
  }

  log(`[experiment] DONE: reply-window-forward ${tabId} ready for new recipients`);
  return true;
}

/* ======================================================================
 * processComposeTab
 * ====================================================================== */
async function processComposeTab(tabId) {
  debug(`processComposeTab(${tabId}): checking processedTabIds.has(${tabId}) = ${processedTabIds.has(tabId)}`);
  if (processedTabIds.has(tabId)) return;
  /* Claim synchronously before the first await. tabs.onCreated and the startup
   * scan can discover the same compose tab concurrently after an add-on update. */
  processedTabIds.add(tabId);

  /* NEVER process compose windows that THIS plugin opened (e.g. from the
   * embedded experiment's beginForward/beginReply). Processing them is what
   * caused the runaway cascade of windows. */
  if (selfOpenedTabIds.has(tabId)) {
    debug(`processComposeTab(${tabId}): self-opened tab, skipping`);
    return;
  }

  debug(`processComposeTab(${tabId}): waiting for compose details...`);
  const details = await waitForComposeDetails(tabId);
  if (!details) {
    debug(`processComposeTab(${tabId}): no details, aborting`);
    return;
  }

  debug(`processComposeTab(${tabId}): type="${details.type}", relatedMessageId=${details.relatedMessageId}, isPlainText=${details.isPlainText}`);

  const relatedMessageId = details.relatedMessageId;
  if (!relatedMessageId) {
    debug(`processComposeTab(${tabId}): no relatedMessageId, skipping (forward-from-file?)`);
    return;
  }

  /* The ForwardIntercept experiment redirects an embedded forward into a
   * *reply* tab. Type "reply" normally means a genuine reply (we pass it
   * through), but when the experiment is enabled and the related message is an
   * embedded smime container, that reply was produced by OUR redirect — clean
   * it (clear recipients, retitle Re:->Fwd:) instead of skipping it. */
  if (details.type === "reply") {
    debug(`processComposeTab(${tabId}): type "reply" — checking redirected-forward marker`);
    /* Only a reply window actually created by OUR Forward->Reply redirect gets
     * cleaned (recipients cleared, Re:->Fwd:). A plain manual "Reply" clicked by
     * the user on the same embedded S/MIME message must be left untouched — the
     * ComposeMessage hook sets redirectPending synchronously when it redirects a
     * Forward, and getAndClearRedirectPending consumes it for exactly one reply
     * tab. If it is not pending, this is a genuine user-initiated reply: skip. */
    let redirectedByUs = false;
    const fi = browser.ForwardIntercept;
    if (fi && typeof fi.getAndClearRedirectPending === "function") {
      redirectedByUs = await fi.getAndClearRedirectPending();
    }
    debug(`processComposeTab(${tabId}): reply tab, redirectPending=${redirectedByUs}`);
    if (!redirectedByUs) {
      return;
    }
    const rct = await getRootContentType(relatedMessageId);
    const isEmbedded = (rct || "").toLowerCase() === "message/rfc822";
    if (!isEmbedded || !(await isSmimeEncrypted(relatedMessageId)) || !(await canDecrypt(relatedMessageId))) {
      return;
    }
    let ok = false;
    try {
      ok = await handleExperimentReplyTab(tabId, relatedMessageId);
    } catch (e) {
      warn("handleExperimentReplyTab failed", e);
    }
    if (ok) return;
    /* On failure fall through to normal forward-ish cleanup paths below. */
  }

  /* Only act on forwards (embedded reply-transform above returns early) */
  if (details.type !== "forward") {
    debug(`processComposeTab(${tabId}): type is "${details.type}" (not "forward"), skipping`);
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

  log(`processing forward compose tab ${tabId} for messageId ${relatedMessageId}`);

  /* Branch on the root content type. A message/rfc822 root means the S/MIME
   * envelope is nested inside an embedded container, which the messages API
   * cannot decrypt — route to the experimental handler (debug build).
   * A normal top-level S/MIME message (application/pkcs7-mime) uses the
   * standard rebuild path. */
  const rootType = await getRootContentType(relatedMessageId);
  debug(`processComposeTab(${tabId}): root content-type = "${rootType}"`);
  const isEmbeddedContainer = (rootType || "").toLowerCase() === "message/rfc822";

  if (isEmbeddedContainer) {
    /* ForwardIntercept normally redirects this before a forward tab exists.
     * Do not resurrect the obsolete two-window fallback if interception failed. */
    warn(`processComposeTab(${tabId}): embedded forward was not intercepted; leaving it unchanged`);
    return;
  } else {
    try {
      await rebuildForwardCompose(tabId, relatedMessageId, details);
    } catch (e) {
      warn("rebuildForwardCompose failed", e);
    }
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
    closedTabIds.delete(tab.id);
    debug(`tabs.onCreated: messageCompose detected, calling processComposeTab(${tab.id})`);
    processComposeTab(tab.id);
  }
});

/* Catch smime.p7m arriving late (after our initial pass) or before the tab
 * has been fully processed. We remove the S/MIME envelope attachment on ANY
 * compose tab as soon as it appears: an smime.p7m/.p7s is the crypto envelope,
 * never something the user wants to send along. Relying on processedTabIds here
 * was a bug — the attachment can be added before processComposeTab marks the
 * tab processed, so it slipped through and got forwarded. */
browser.compose.onAttachmentAdded.addListener((tab, attachment) => {
  debug(`onAttachmentAdded: tab=${tab?.id}, attachment.name=${attachment?.name}, attachment.id=${attachment?.id}`);
  if (!tab || !tab.id) return;
  const tabId = tab.id;
  const n = (attachment && attachment.name || "").toLowerCase();
  if (n === "smime.p7m" || n === "smime.p7s" || n.endsWith(".p7m") || n.endsWith(".p7s")) {
    const key = `${tabId}:${attachment.id}`;
    if (removingAttachmentKeys.has(key)) {
      debug(`duplicate smime removal ignored for ${key}`);
      return;
    }
    removingAttachmentKeys.add(key);
    log(`removing smime envelope attachment "${attachment.name}" on tab ${tabId}`);
    browser.compose.removeAttachment(tabId, attachment.id)
      .catch(e => warn("late remove failed", e))
      .finally(() => removingAttachmentKeys.delete(key));
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

  /* ForwardIntercept is the supported embedded-message implementation and is
   * always active. */
  try {
    const ok = await browser.ForwardIntercept.setEnabled(true);
    log(`ForwardIntercept ${ok ? "ENABLED" : "enable FAILED"}`);
  } catch (e) {
    warn("ForwardIntercept.setEnabled failed:", e);
  }

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
