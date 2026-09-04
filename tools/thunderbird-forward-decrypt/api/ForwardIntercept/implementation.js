/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * ForwardIntercept — privileged (parent) implementation.
 *
 * Intercepts the *Forward* action of an embedded message/rfc822 S/MIME
 * container. The WebExtension compose API cannot intercept the Forward
 * button/menu/command — those dispatch through the 3-pane window's
 * ComposeMessage() function in the main process. An Experiment runs in that
 * same privileged scope, so it can hook ComposeMessage() on every mail:3pane
 * window and rewrite a forward of an embedded container into a reply BEFORE
 * the compose window is created. This gives the user a single reply window
 * (with the full decrypted content) and no empty Forward-window flash.
 *
 * Why patch ComposeMessage() (a plain JS function on the window scope) instead
 * of nsIMsgComposeService: the XPCOM service's interface methods are read-only
 * from JS, so assigning a wrapper on the service instance silently does not
 * take effect. Window-scope JS functions are reassignable, so this hook is
 * reliable.
 */

"use strict";

var { ExtensionCommon } = ChromeUtils.importESModule(
  "resource://gre/modules/ExtensionCommon.sys.mjs"
);

/* Thunderbird's own attachment-extraction engine. MsgHdrToMimeMessage streams
 * the (decrypted) message through gloda's jsmimeemitter and hands back a
 * MimeMessage tree. With {examineEncryptedParts:true} the S/MIME parts are
 * decrypted (S/MIME "is not that smart, and always decrypts data" when
 * requested), producing the same decrypted MIME tree the message reader
 * displays — including inside embedded message/rfc822 containers. This is the
 * path Thunderbird itself uses to build attachment lists, unlike the
 * WebExtension messages API whose getFull() is hardcoded to
 * decodeSubMessages:false and therefore cannot descend into an embedded rfc822
 * to reach a nested S/MIME envelope. */
var { MsgHdrToMimeMessage } = ChromeUtils.importESModule(
  "resource:///modules/gloda/MimeMessage.sys.mjs"
);
var { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
var { NetUtil } = ChromeUtils.importESModule(
  "resource://gre/modules/NetUtil.sys.mjs"
);

var ForwardIntercept = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    /* Tracks whether we are intercepting. Default OFF; the background script
     * enables it (mirrors the v0.2.x "experiments" option so the code path is
     * inert unless explicitly turned on). */
    let enabled = false;

    /* Most recent message URI that a forward was invoked on (when we redirect
     * it into a reply). The background script pulls this with getLastForwardUri
     * and feeds it to extractDecryptedAttachments() so the parent can run
     * Thunderbird's own decryption/extraction on the real message. */
    let lastForwardUri = null;

    function uriOf(arg) {
      try {
        if (arg && arg.folder && typeof arg.folder.getUriForMsg === "function") {
          return arg.folder.getUriForMsg(arg);
        }
      } catch (_) {}
      try {
        return String(arg);
      } catch (_) {
        return null;
      }
    }

    /* Compose-type constants (nsIMsgCompType). Only the ones we need. */
    const COMPOSE_TYPE = {
      ForwardAsAttachment: 3,
      ForwardInline: 4,
      ReplyToSender: 6,
    };

    const patchedWindows = new WeakMap();

    function isForwardType(type) {
      return (
        type === COMPOSE_TYPE.ForwardInline ||
        type === COMPOSE_TYPE.ForwardAsAttachment
      );
    }

    function patchWindow(win) {
      if (!win || win.closed) {
        return;
      }

      if (patchedWindows.has(win)) {
        return;
      }

      const original = win.ComposeMessage;

      if (typeof original !== "function") {
        Services.console.logStringMessage(
          "[ForwardIntercept] ComposeMessage not found"
        );
        return;
      }

      Services.console.logStringMessage(
        `[ForwardIntercept] patch target: href=${win.location?.href}, ` +
          `typeof ComposeMessage=${typeof win.ComposeMessage}`
      );

      const wrapped = function (...args) {
        Services.console.logStringMessage(
          `[ForwardIntercept] ComposeMessage CALLED type=${args[0]}`
        );

        try {
          const [type, format, folder, messageArray] = args;

          if (
            enabled &&
            isForwardType(type) &&
            messageArray &&
            messageArray.length === 1
          ) {
            Services.console.logStringMessage(
              `[ForwardIntercept] REDIRECT Forward -> ReplyToSender: ${messageArray[0]}`
            );

            /* Remember which message the forward was for. Used later by the
             * background script to decrypt + re-attach standalone files. */
            lastForwardUri = uriOf(messageArray[0]);
            Services.console.logStringMessage(
              `[ForwardIntercept] capture lastForwardUri=${lastForwardUri}`
            );

            args[0] = COMPOSE_TYPE.ReplyToSender;
          }
        } catch (e) {
          Services.console.logStringMessage(
            `[ForwardIntercept] wrapper error: ${e}`
          );
        }

        return original.call(this, ...args);
      };

      win.ComposeMessage = wrapped;

      patchedWindows.set(win, {
        original,
        wrapped,
      });

      Services.console.logStringMessage(
        "[ForwardIntercept] ComposeMessage patched"
      );
    }

    function unpatchWindow(win) {
      const state = patchedWindows.get(win);

      if (!state) {
        return;
      }

      try {
        if (win.ComposeMessage === state.wrapped) {
          win.ComposeMessage = state.original;
        }
      } catch (_) {}

      patchedWindows.delete(win);
    }

    function patchAllWindows() {
      const enumerator = Services.wm.getEnumerator("mail:3pane");

      while (enumerator.hasMoreElements()) {
        try {
          const xulWindow = enumerator.getNext();
          const win = xulWindow.docShell?.domWindow;

          if (win) {
            patchWindow(win);
          }
        } catch (e) {
          Services.console.logStringMessage(
            `[ForwardIntercept] patchWindow failed: ${e}`
          );
        }
      }
    }

    function isPatchableWindow(win) {
      try {
        const href = win.location?.href || "";
        return (
          href.includes("messenger.xhtml") || href.includes("about:3pane")
        );
      } catch (_) {
        return false;
      }
    }

    const windowListener = {
      onOpenWindow(xulWindow) {
        const win = xulWindow.docShell?.domWindow;

        if (!win) {
          return;
        }

        win.addEventListener(
          "load",
          () => {
            try {
              if (isPatchableWindow(win)) {
                patchWindow(win);
              }
            } catch (_) {}
          },
          { once: true }
        );
      },

      onCloseWindow(xulWindow) {
        const win = xulWindow.docShell?.domWindow;

        try {
          unpatchWindow(win);
        } catch (_) {}
      },

      onWindowTitleChange() {},
    };

    function install() {
      Services.wm.addListener(windowListener);
      patchAllWindows();

      Services.console.logStringMessage(
        "[ForwardIntercept] installed"
      );

      return true;
    }

    function uninstall() {
      try {
        Services.wm.removeListener(windowListener);
      } catch (_) {}

      const enumerator = Services.wm.getEnumerator("mail:3pane");

      while (enumerator.hasMoreElements()) {
        try {
          unpatchWindow(enumerator.getNext());
        } catch (_) {}
      }

      Services.console.logStringMessage(
        "[ForwardIntercept] uninstalled"
      );
    }

    /* Read the attachment model Thunderbird built for a compose window. When
     * the user forwards an embedded message/rfc822 S/MIME container, we
     * redirect it into a reply, and Thunderbird's compose (in the parent
     * process) materializes the DECRYPTED message into its nsIMsgCompFields.
     * The WebExtension messages API cannot reach those decrypted parts, but
     * the compose window's gMsgComposeFields.attachments can. This reports
     * what Thunderbird actually holds for the reply, so we know whether the
     * standalone file (e.g. TEst.txt) is being carried and forwarded, or is
     * dropped entirely (which would require parent-side extraction). */
    function readComposeAttachments() {
      const rows = [];
      const wins = [...Services.wm.getEnumerator("msgcompose")];
      Services.console.logStringMessage(
        `[ForwardIntercept] getComposeAttachments: ${wins.length} compose window(s)`
      );

      for (const win of wins) {
        /* Find the CompFields accessor that exists on this window global. */
        let fields = null;
        for (const k of ["gMsgComposeFields", "mMsgComposeFields", "msgComposeFields"]) {
          try {
            if (win?.[k]) { fields = win[k]; break; }
          } catch (_) {}
        }
        if (!fields) {
          Services.console.logStringMessage(
            "[ForwardIntercept] getComposeAttachments: no CompFields accessor on a compose window"
          );
          continue;
        }

        let atts = null;
        try { atts = fields.attachments; } catch (_) {}
        if (!atts) {
          Services.console.logStringMessage(
            "[ForwardIntercept] getComposeAttachments: CompFields has no attachments array"
          );
          continue;
        }

        for (const att of atts) {
          try {
            const name = (att.name || "").toString();
            const lower = name.toLowerCase();
            if (lower.endsWith(".p7m") || lower.endsWith(".p7s")) continue;
            let size = 0;
            try { size = typeof att.getSize === "function" ? att.getSize() : (att.size || 0); } catch (_) {}
            const disp = (att.contentDisposition || (typeof att.getContentDisposition === "function" ? att.getContentDisposition() : "")).toString();
            rows.push({
              name,
              size,
              contentType: (att.contentType || (typeof att.getContentType === "function" ? att.getContentType() : "") || "").toString(),
              isInline: disp === "inline",
            });
          } catch (e) {
            Services.console.logStringMessage(
              `[ForwardIntercept] getComposeAttachments: skip attachment err: ${e}`
            );
          }
        }
      }

      return rows;
    }

    /* ---- Decrypted-attachment extraction (Path B) ---- */

    /* Read a MIME part URL (e.g. imap://…?part=1.1.1.1.2) into a base64 string.
     * The correct Thunderbird primitive for a part URL is NetUtil.asyncFetch
     * (NOT messageServiceFromURI().streamMessage, which needs a whole-message
     * URI and fails with NS_MSG_ERROR_FOLDER_MISSING). Thunderbird's main-process
     * URL handler serves the DECRYPTED part content, and loadUsingSystemPrincipal
     * bypasses the nullprincipal security block the reader hits when it tries to
     * fetch these same URLs. */
    async function streamUrlToBase64(url) {
      try {
        const sourceURI = Services.io.newURI(url);
        const buffer = await new Promise((resolve, reject) => {
          NetUtil.asyncFetch(
            {
              uri: sourceURI,
              loadUsingSystemPrincipal: true,
            },
            (inputStream, status) => {
              if (Components.isSuccessCode(status)) {
                try {
                  resolve(NetUtil.readInputStream(inputStream));
                } catch (e) {
                  reject(e);
                }
              } else {
                reject(
                  new Components.Exception(
                    `Failed to fetch ${url} (${status})`,
                    status
                  )
                );
              }
            }
          );
        });
        if (!buffer) return "";
        if (typeof btoa !== "function") return "";
        /* readInputStream historically returned a Latin-1 string; newer
         * Thunderbird returns an ArrayBuffer. Handle both. */
        if (typeof buffer === "string") {
          return btoa(buffer);
        }
        const u8 =
          buffer instanceof Uint8Array
            ? buffer
            : new Uint8Array(buffer || 0);
        let s = "";
        for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
        return btoa(s);
      } catch (e) {
        Services.console.logStringMessage(
          `[ForwardIntercept] streamUrlToBase64(${url}) err: ${e}`
        );
        return "";
      }
    }

    function mimeHeader(node, name) {
      try {
        if (!node || !node.headers) return null;
        if (typeof node.headers.get === "function") {
          const v = node.headers.get(name);
          return v == null ? null : String(v);
        }
        const v = node.headers[name] || node.headers[name.toLowerCase()];
        if (Array.isArray(v)) return v.join(" ");
        return v == null ? null : String(v);
      } catch (_) {
        return null;
      }
    }

    /* Recursively gather the real (non-envelope, non-inline) file attachments
     * Thunderbird exposed for the decrypted message. Handles leaves that gloda
     * materialized either as a MimeMessageAttachment (streamable .url) or as a
     * MimeBody (in-memory .body). */
    function walkDecryptedParts(node, out) {
      if (!node) return;
      const ct = (node.contentType || "").toLowerCase();
      const cd = (mimeHeader(node, "content-disposition") || "").toLowerCase();
      const cid = mimeHeader(node, "content-id");
      const isEnvelope =
        ct.includes("pkcs7-mime") ||
        ct.includes("enveloped-data") ||
        (node.name || "").toLowerCase().endsWith(".p7m") ||
        (node.name || "").toLowerCase().endsWith(".p7s");

      if (node.url) {
        if (!isEnvelope) {
          const isInline =
            cd.includes("inline") ||
            (ct.startsWith("image/") && (cid || cd.includes("inline")));
          out.push({
            name: node.name || "attachment",
            contentType: node.contentType || "",
            url: node.url,
            isInline: !!isInline,
            body: null,
          });
        }
      } else if (
        typeof node.body === "string" &&
        node.name &&
        (node.parts ? node.parts.length : 0) === 0 &&
        !isEnvelope
      ) {
        const isInline = cd.includes("inline");
        out.push({
          name: node.name,
          contentType: node.contentType || "",
          url: null,
          isInline: !!isInline,
          body: node.body,
        });
      }

      for (const c of node.parts || []) {
        walkDecryptedParts(c, out);
      }
    }

    function runExtractDecryptedAttachments(messageUri) {
      const empty = { rows: [], log: [] };
      const logMsg = s => Services.console.logStringMessage(`[ForwardIntercept] extract: ${s}`);
      if (!messageUri) {
        logMsg("no messageUri");
        return Promise.resolve(empty);
      }

      let msgHdr = null;
      try {
        const service = MailServices.messageServiceFromURI(messageUri);
        if (!service) {
          logMsg(`no message service for ${messageUri}`);
          return Promise.resolve(empty);
        }
        msgHdr = service.messageURIToMsgHdr(messageUri);
      } catch (e) {
        logMsg(`messageURIToMsgHdr failed: ${e}`);
        return Promise.resolve(empty);
      }
      if (!msgHdr) {
        logMsg(`no msgHdr for ${messageUri}`);
        return Promise.resolve(empty);
      }

      let resolveGot;
      const got = new Promise(r => (resolveGot = r));

      try {
        MsgHdrToMimeMessage(
          msgHdr,
          null,
          (_hdr, mimeMsg) => {
            (async () => {
              const rows = [];
              const notes = [];
              try {
                const parts = [];
                walkDecryptedParts(mimeMsg, parts);
                notes.push(`${parts.length} exposed part(s)`);
                for (const p of parts) {
                  notes.push(
                    `candidate ${p.name} | ${p.contentType} | inline=${p.isInline} | url=${p.url ? "yes" : "in-body"}`
                  );
                  if (p.isInline) continue;
                  let b64 = "";
                  if (p.url) {
                    b64 = await streamUrlToBase64(p.url);
                  } else if (p.body !== null && p.body !== undefined) {
                    b64 = typeof btoa === "function" ? btoa(String(p.body)) : "";
                  }
                  if (b64) {
                    rows.push({
                      name: p.name,
                      contentType: p.contentType,
                      size: (b64.length * 3) / 4,
                      dataBase64: b64,
                    });
                    notes.push(`-> GOT bytes for ${p.name} (${rows[rows.length - 1].size}b)`);
                  } else {
                    notes.push(`-> NO BYTES for ${p.name}`);
                  }
                }
              } catch (e) {
                notes.push(`walk failed: ${e}`);
              }
              logMsg(JSON.stringify(notes));
              resolveGot({ rows, log: notes });
            })();
          },
          true /* aAllowDownload: stream the real message, not just headers */,
          { examineEncryptedParts: true, partsOnDemand: true }
        );
      } catch (e) {
        logMsg(`MsgHdrToMimeMessage threw: ${e}`);
        resolveGot(empty);
      }

      return got;
    }

    return {
      ForwardIntercept: {
        async getEnabled() {
          return enabled;
        },

        async setEnabled(value) {
          value = !!value;

          if (value === enabled) {
            return enabled;
          }

          if (value) {
            if (!install()) {
              return false;
            }
          } else {
            uninstall();
          }

          enabled = value;
          return enabled;
        },

        async getComposeAttachments(tabId) {
          return readComposeAttachments(tabId);
        },

        async getLastForwardUri() {
          return lastForwardUri;
        },

        async extractDecryptedAttachments(messageUri) {
          return runExtractDecryptedAttachments(messageUri);
        },
      },
    };
  }
};