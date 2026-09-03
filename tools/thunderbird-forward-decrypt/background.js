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
/* Embedded-container experiment (opens forward/reply windows) is OFF by
 * default. It must be explicitly enabled in storage to run — it is unsafe
 * to auto-run (caused an unbounded window cascade). */
let experimentsEnabled = false;

async function loadDebugFlag() {
  try {
    const { debug, experiments } = await browser.storage.local.get(["debug", "experiments"]);
    debugEnabled = !!debug;
    experimentsEnabled = !!experiments;
  } catch (_) { debugEnabled = false; experimentsEnabled = false; }
}

// Listen for storage changes (real-time toggle without restart)
browser.storage.onChanged.addListener(async (changes, area) => {
  if (area === "local") {
    if (changes.debug) {
      debugEnabled = !!changes.debug.newValue;
      log(`debug mode ${debugEnabled ? "ENABLED" : "DISABLED"}`);
    }
    if (changes.experiments) {
      experimentsEnabled = !!changes.experiments.newValue;
      log(`embedded experiment ${experimentsEnabled ? "ENABLED" : "DISABLED"}`);
      /* Reflect the toggle into the privileged ForwardIntercept experiment. */
      try {
        if (browser.ForwardIntercept) {
          const ok = await browser.ForwardIntercept.setEnabled(experimentsEnabled);
          log(`ForwardIntercept runtime ${experimentsEnabled ? "ENABLED" : "DISABLED"} (${ok})`);
        }
      } catch (e) {
        warn("ForwardIntercept runtime toggle failed:", e);
      }
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
/* Tabs opened by THIS plugin (e.g. beginForward / beginReply) — these must
 * NEVER be re-processed, otherwise the experimental embedded-handler would
 * cascade and spawn unbounded compose windows. */
const selfOpenedTabIds  = new Set();
/* messageIds for which the embedded experiment has already run — prevent
 * re-running it for the same container (even from user-opened windows). */
const handledEmbeddedMessageIds = new Set();
/* Global re-entrancy lock for the embedded experiment. */
let embeddedExperimentRunning = false;

/* Clean up on tab close */
browser.tabs.onRemoved.addListener(tabId => {
  debug(`tab ${tabId} closed, cleaning up`);
  processedTabIds.delete(tabId);
  pendingTabPollers.delete(tabId);
  selfOpenedTabIds.delete(tabId);
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
 * experimentalHandleEmbedded
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
      toRecipients: [],
      ccRecipients: [],
      bccRecipients: [],
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

  /* Give real file attachments / inline images time to materialize (mirrors
   * handleEmbeddedForward). */
  await sleep(3000);
  const d = await waitForComposeDetails(tabId);
  if (!d) {
    warn(`[experiment] reply window ${tabId}: could not read compose details`);
    return false;
  }

  try {
    await browser.compose.setComposeDetails(tabId, {
      toRecipients: [],
      ccRecipients: [],
      bccRecipients: [],
    });
    log(`[experiment] recipients cleared on reply window ${tabId}`);
  } catch (e2) {
    warn("[experiment] clearing recipients FAILED:", e2);
  }

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

  log(`[experiment] DONE: reply-window-forward ${tabId} ready for new recipients`);
  return true;
}

/* ======================================================================
 * EXPERIMENTAL (debug build): for a message/rfc822 container whose S/MIME
 * envelope cannot be reached via the messages API (getFull/listInlineTextParts
 * /listAttachments do not surface the decrypted inner content), open
 * compose.beginForward(...) and compose.beginReply(...) on the container and
 * log what getComposeDetails returns (body, plainTextBody, attachments).
 * The opened windows are intentionally LEFT OPEN for visual inspection.
 * This collects facts so we can decide the final implementation.
 * ====================================================================== */
async function experimentalHandleEmbedded(tabId, messageId) {
  debug(`[experiment] rootType=message/rfc822 for messageId ${messageId}, tab ${tabId} — entering embedded experiment`);

  /* Re-entrancy guard: never run the experiment twice at once and never
   * re-run it for the same container. Prevents the infinite cascade of
   * compose windows caused by the plugin opening windows that itself then
   * processes. */
  if (embeddedExperimentRunning) {
    debug(`[experiment] already running, aborting re-entrant call for messageId ${messageId}`);
    return;
  }
  if (handledEmbeddedMessageIds.has(messageId)) {
    debug(`[experiment] messageId ${messageId} already handled, skipping`);
    return;
  }
  handledEmbeddedMessageIds.add(messageId);
  embeddedExperimentRunning = true;

  async function listAtts(tabId) {
    try {
      const list = await browser.compose.listAttachments(tabId);
      return (list || []).map(a => ({ id: a.id, name: a.name, size: a.size, type: a.type }));
    } catch (e) {
      warn(`[experiment] ${name}: listAttachments failed:`, e.message || e);
      return null;
    }
  }

  async function inspectTab(name, openFn, delayMs) {
    const winTab = await openFn();
    debug(`[experiment] ${name}: compose window opened, tabId=${winTab?.id}`);
    /* Mark the window we opened so processComposeTab skips it — this is the
     * key guard against the infinite window cascade. */
    if (winTab && winTab.id) selfOpenedTabIds.add(winTab.id);
    const tabId = winTab && winTab.id;
    const d = await waitForComposeDetails(tabId);
    if (!d) {
      debug(`[experiment] ${name}: could not read compose details`);
      return null;
    }
    const atts = (d.attachments || []).map(a => ({ name: a.name, size: a.size, type: a.type }));
    debug(`[experiment] ${name}: getComposeDetails (t0) =>`,
      { type: d.type,
        subject: d.subject,
        bodyLen: d.body ? d.body.length : undefined,
        plainTextBodyLen: d.plainTextBody ? d.plainTextBody.length : undefined,
        to: (d.toRecipients || []), cc: (d.ccRecipients || []),
        attachments: atts, encryption: d.encryption });

    /* Real file attachments may arrive LATER than the visible body (like the
     * smime envelope does). Re-read the attachment list after a delay to see
     * whether e.g. the forwarded txt file is materialized. */
    if (delayMs) {
      await sleep(delayMs);
      const later = await listAtts(tabId);
      debug(`[experiment] ${name}: attachments after +${delayMs}ms =>`, later);
    }
    return d;
  }

  try {
    const fwd = await inspectTab("beginForward(container)", () =>
      browser.compose.beginForward(messageId, "forwardInline"), 4000);

    const rep = await inspectTab("beginReply(container)", () =>
      browser.compose.beginReply(messageId, "replyToSender"), 8000);

    const fwdBody = fwd && (fwd.body || fwd.plainTextBody) ? fwd.body && fwd.body.length || (fwd.plainTextBody && fwd.plainTextBody.length) : 0;
    const repBody = rep && (rep.body || rep.plainTextBody) ? rep.body && rep.body.length || (rep.plainTextBody && rep.plainTextBody.length) : 0;
    const fwdAtts = fwd ? (fwd.attachments || []).filter(a => !/\.p7[ms]$/i.test(a.name || "")).length : 0;
    const repAtts = rep ? (rep.attachments || []).filter(a => !/\.p7[ms]$/i.test(a.name || "")).length : 0;

    debug(`[experiment] CONCLUSION: forward => bodyLen=${fwdBody}, realAttachments=${fwdAtts}; reply => bodyLen=${repBody}, realAttachments=${repAtts}. Windows left open for inspection.`);

    /* ---- DEEP PROBE: can we see the decrypted inner parts at all? ---- */
    try {
      const full = await browser.messages.getFull(messageId, { decrypt: true });
      debug(`[experiment][deep] getFull(decrypt:true) root:`,
        { contentType: full?.contentType, decryptionStatus: full?.decryptionStatus, partCount: (full?.parts || []).length });
      walkParts(full, (p, pathName) => {
        debug(`[experiment][deep:decrypt] part ${pathName || "(root)"}:`,
          { contentType: p.contentType, disposition: p.contentDisposition, name: p.name, partName: p.partName,
            size: p.size, bodyLen: (p.body != null) ? p.body.length : undefined,
            subParts: (p.parts || []).length });
      });
    } catch (e) {
      warn(`[experiment][deep] getFull(decrypt:true) FAILED:`, e.message || e);
    }

    /* Try messages.listAttachments (decryption-aware) and pull each file. */
    try {
      const atts = await browser.messages.listAttachments(messageId);
      debug(`[experiment][deep] messages.listAttachments(${messageId}) =>`, (atts || []).map(a =>
        ({ name: a.name, size: a.size, partName: a.partName, contentType: a.contentType })));
      for (const a of (atts || [])) {
        for (const pn of [a.partName].filter(Boolean)) {
          try {
            const f = await browser.messages.getAttachmentFile(messageId, pn);
            debug(`[experiment][deep] getAttachmentFile(${messageId}, "${pn}") OK: size=${f && f.size} type=${f && f.type}`);
          } catch (e2) {
            warn(`[experiment][deep] getAttachmentFile(${messageId}, "${pn}") FAILED:`, e2.message || e2);
          }
        }
      }
    } catch (e) {
      warn(`[experiment][deep] messages.listAttachments FAILED:`, e.message || e);
    }

    /* Try retrieving the decrypted inner parts directly by their partName.
     * The inline image src / txt are at part 1.x inside the smime.p7m CMS;
     * if getAttachmentFile can address them from the decrypted message, we
     * can recover the images/attachments for the forward. */
    for (const pn of ["1", "1.1", "1.1.1", "1.1.1.1", "1.1.1.1.2", "1.1.1.1.3", "1.1.2", "1.2"]) {
      try {
        const f = await browser.messages.getAttachmentFile(messageId, pn);
        debug(`[experiment][deep] getAttachmentFile(${messageId}, "${pn}") OK: size=${f && f.size} type=${f && f.type}`);
      } catch (e3) {
        debug(`[experiment][deep] getAttachmentFile(${messageId}, "${pn}") ->`, (e3 && e3.message) || e3);
      }
    }
  } finally {
    embeddedExperimentRunning = false;
  }
}

/* ======================================================================
 * processComposeTab
 * ====================================================================== */
async function processComposeTab(tabId) {
  debug(`processComposeTab(${tabId}): checking processedTabIds.has(${tabId}) = ${processedTabIds.has(tabId)}`);
  if (processedTabIds.has(tabId)) return;

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
  if (details.type === "reply" && experimentsEnabled) {
    debug(`processComposeTab(${tabId}): type "reply" with experimentsEnabled — checking redirect case`);
    if (processedTabIds.has(tabId)) return;
    processedTabIds.add(tabId);
    const rct = await getRootContentType(relatedMessageId);
    const isEmbedded = (rct || "").toLowerCase() === "message/rfc822";
    if (!isEmbedded || !(await isSmimeEncrypted(relatedMessageId)) || !(await canDecrypt(relatedMessageId))) {
      processedTabIds.delete(tabId);
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

  processedTabIds.add(tabId);
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
    /* message/rfc822 container: the full decrypted content (body, inline
     * images, attachments) is only reachable through a reply window, which
     * handleEmbeddedForward rebuilds and leaves for the user (original forward
     * window is closed). The diagnostic experiment only runs if that fails. */
    log(`processComposeTab(${tabId}): embedded message/rfc822 container — rebuilding as reply`);
    let ok = false;
    try {
      ok = await handleEmbeddedForward(tabId, relatedMessageId, details);
    } catch (e) {
      warn("handleEmbeddedForward failed", e);
    }
    if (experimentsEnabled && !ok) {
      try {
        await experimentalHandleEmbedded(tabId, relatedMessageId);
      } catch (e) {
        warn("experimentalHandleEmbedded failed", e);
      }
    }
    /* Successful reply-forward closes the original forward tab — no sweeps on
     * it. On failure the tab may still be open; sweep it anyway. */
    if (ok) return;
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
    log(`removing smime envelope attachment "${attachment.name}" on tab ${tabId}`);
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

  /* Enable the ForwardIntercept experiment if the experiments option is on.
   * This requires the privileged experiment_apis (0.2.2); it redirects an
   * embedded message/rfc822 forward into a reply at compose-open time. If the
   * API is unavailable (e.g. plain build), this no-ops and the classic
   * handleEmbeddedForward two-window fallback is used instead. */
  if (experimentsEnabled) {
    try {
      const ok = await browser.ForwardIntercept.setEnabled(true);
      log(`ForwardIntercept experiment ${ok ? "ENABLED" : "enable FAILED"}`);
    } catch (e) {
      warn("ForwardIntercept.setEnabled failed (experiment_apis unavailable?):", e);
    }
  } else {
    log("ForwardIntercept experiment disabled (experiments option off)");
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
