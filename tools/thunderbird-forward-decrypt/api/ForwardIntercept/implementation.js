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
var { setTimeout } = ChromeUtils.importESModule(
  "resource://gre/modules/Timer.sys.mjs"
);

/* Attachment extraction (Path B). The parts of an embedded message/rfc822
 * S/MIME container are NOT reachable through the WebExtension messages API:
 * getFull() is hardcoded to decodeSubMessages:false, so MimeMessage.getFull()
 * only yields the outer envelope. Instead we do what Thunderbird's message
 * reader + MimeTree machinery does: stream the RAW message in the parent
 * scope, then decrypt it with Thunderbird's own MimeTreeDecrypter (which is
 * "not that smart" and always decrypts S/MIME, including a nested envelope),
 * then re-parse the decrypted MIME with the MimeTreeEmitter and read each
 * attachment's body bytes directly. No gloda part-URL fetch involved. */
var { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
var {
  MimeTreeDecrypter,
  MimeTreeEmitter,
  getMimeTree,
  mimeTreeToString,
} = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/MimeTree.sys.mjs"
);
var { jsmime } = ChromeUtils.importESModule(
  "resource:///modules/jsmime.sys.mjs"
);

var ForwardIntercept = class extends ExtensionCommon.ExtensionAPI {
  onStartup() {
    /* MV3 background scripts are event pages and may otherwise stay asleep
     * until the first compose tab is created, which is already too late to
     * intercept the command that created it. Loading this Experiment for the
     * startup lifecycle event lets us wake the background before user input. */
    Services.console.logStringMessage(
      "[ForwardIntercept] startup: waking extension background"
    );
    return this.extension.wakeupBackground();
  }

  getAPI(context) {
    /* getAPI() is called again whenever Thunderbird recreates the MV3
     * background context. The privileged ComposeMessage wrapper outlives that
     * context, so its marker/URI state must outlive it too. Reuse the original
     * API closure instead of installing a second wrapper with fresh state. */
    if (this._sharedAPI) {
      Services.console.logStringMessage(
        "[ForwardIntercept] getAPI: reusing shared state after background wake"
      );
      return { ForwardIntercept: this._sharedAPI };
    }

    /* Tracks whether we are intercepting. Default OFF; the background script
     * enables it (mirrors the v0.2.x "experiments" option so the code path is
     * inert unless explicitly turned on). */
    let enabled = false;

    /* Most recent message URI that a forward was invoked on (when we redirect
     * it into a reply). The background script pulls this with getLastForwardUri
     * and feeds it to extractDecryptedAttachments() so the parent can run
     * Thunderbird's own decryption/extraction on the real message. */
    let lastForwardUri = null;

    /* Set synchronously by the ComposeMessage wrapper the moment it redirects a
     * Forward into a ReplyToSender. The background script consumes + clears it
     * (getAndClearRedirectPending) when the resulting reply compose tab arrives,
     * so we can tell the window WE redirected from a plain manual "Reply"
     * clicked on the same (embedded S/MIME) message — only the former must have
     * its recipients cleared and subject retitled Re:->Fwd:. */
    let redirectPending = false;

    /* Readiness of the compose window created by the most recent redirected
     * Forward. Thunderbird exposes the exact point at which quoted reply body
     * construction is complete through nsIMsgComposeStateListener. Keeping the
     * resolved promise also covers fast machines where BodyReady fires before
     * the WebExtension background reaches its wait call. */
    let redirectComposeReady = null;

    function newRedirectComposeReady() {
      let finish;
      const state = {
        settled: false,
        window: null,
        promise: new Promise(resolve => { finish = resolve; }),
        resolve(result) {
          if (state.settled) return;
          state.settled = true;
          finish(result);
        },
      };
      return state;
    }

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
            redirectPending = true;
            redirectComposeReady = newRedirectComposeReady();
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

        /* compose-window-init is dispatched after gMsgCompose exists but
         * before the asynchronous quote/body builder completes. Registering
         * here guarantees that NotifyComposeBodyReady cannot be missed. */
        try {
          const ready = redirectComposeReady;
          if (ready && !ready.settled && !ready.window) {
            win.addEventListener("compose-window-init", () => {
              try {
                if (ready.window || ready.settled) return;
                ready.window = win;
                win.addEventListener("unload", () => ready.resolve("closed"), { once: true });
                const compose = win.gMsgCompose;
                if (!compose || win.closed) {
                  ready.resolve("closed");
                  return;
                }
                const stateListener = {
                  NotifyComposeFieldsReady() {},
                  NotifyComposeBodyReady() {
                    Services.console.logStringMessage(
                      "[ForwardIntercept] redirected compose body ready"
                    );
                    ready.resolve("ready");
                    try { compose.UnregisterStateListener(stateListener); } catch (_) {}
                  },
                  ComposeProcessDone() {},
                  SaveInFolderDone() {},
                  QueryInterface: ChromeUtils.generateQI(["nsIMsgComposeStateListener"]),
                };
                compose.RegisterStateListener(stateListener);
              } catch (e) {
                Services.console.logStringMessage(
                  `[ForwardIntercept] compose readiness listener failed: ${e}`
                );
                ready.resolve("unavailable");
              }
            }, { capture: true, once: true });
          }
        } catch (_) {}

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
          const xulWindow = enumerator.getNext();
          unpatchWindow(xulWindow.docShell?.domWindow || xulWindow);
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

    function mimeHeader(node, name) {
      try {
        if (!node || !node.headers) return null;
        if (typeof node.headers.getRawHeader === "function") {
          const raw = node.headers.getRawHeader(name);
          if (raw != null) return String(raw);
        }
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

    function mimeFilename(node) {
      if (node?.name) return String(node.name);
      for (const [header, parameter] of [
        ["content-disposition", "filename"],
        ["content-type", "name"],
      ]) {
        const value = mimeHeader(node, header) || "";
        const match = new RegExp(
          `(?:^|;)\\s*${parameter}\\s*=\\s*(?:"([^"]*)"|([^;\\s]*))`,
          "i",
        ).exec(value);
        if (match) return match[1] || match[2] || "";
      }
      return "";
    }

    function mimeContentType(node) {
      try {
        const structured = node?.headers?.contentType ||
          node?.headers?.get?.("content-type");
        if (structured?.type) return String(structured.type).toLowerCase();
      } catch (_) {}
      return String(node?.fullContentType || node?.contentType || "")
        .split(";", 1)[0]
        .trim()
        .toLowerCase();
    }

    /* Stream a whole-message URI (e.g. imap-message://…#204) into a string
     * holding the RAW message bytes (one char == one byte). This is the same
     * streaming Thunderbird's message APIs use for full messages; it only fails
     * for part-URLs, which we no longer use. */
    function streamMessageToString(messageUri) {
      return new Promise(resolve => {
        const chunks = [];
        let stream = null;
        const listener = {
          onStartRequest() {},
          onDataAvailable(aRequest, aInputStream, aOffset, aCount) {
            if (!stream) {
              stream = Cc[
                "@mozilla.org/scriptableinputstream;1"
              ].createInstance(Ci.nsIScriptableInputStream);
              stream.init(aInputStream);
            }
            chunks.push(stream.read(aCount));
          },
          onStopRequest(aRequest, status) {
            resolve({
              ok: Components.isSuccessCode(status),
              data: chunks.join(""),
            });
          },
          QueryInterface: ChromeUtils.generateQI([
            "nsIStreamListener",
            "nsIRequestObserver",
          ]),
        };
        try {
          const service = MailServices.messageServiceFromURI(messageUri);
          if (!service) {
            Services.console.logStringMessage(
              `[ForwardIntercept] no message service for ${messageUri}`
            );
            resolve({ ok: false, data: "" });
            return;
          }
          service.streamMessage(messageUri, listener, null, null, false, "");
        } catch (e) {
          Services.console.logStringMessage(
            `[ForwardIntercept] stream ${messageUri} threw: ${e}`
          );
          resolve({ ok: false, data: "" });
        }
      });
    }

    /* Convert a JS string of raw bytes into base64 (Latin-1 safe). */
    function bytesToBase64(data) {
      if (!data) return "";
      const alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      let encoded = "";
      for (let i = 0; i < data.length; i += 3) {
        const a = data.charCodeAt(i) & 0xff;
        const hasB = i + 1 < data.length;
        const hasC = i + 2 < data.length;
        const b = hasB ? data.charCodeAt(i + 1) & 0xff : 0;
        const c = hasC ? data.charCodeAt(i + 2) & 0xff : 0;
        encoded += alphabet[a >> 2];
        encoded += alphabet[((a & 3) << 4) | (b >> 4)];
        encoded += hasB ? alphabet[((b & 15) << 2) | (c >> 6)] : "=";
        encoded += hasC ? alphabet[c & 63] : "=";
      }
      return encoded;
    }

    function byteArrayToString(data) {
      let value = "";
      for (const byte of data || []) value += String.fromCharCode(byte);
      return value;
    }

    /* nsCMSDecoderJS uses NSS_CMSDecoder with a content callback. Despite the
     * method name `decrypt`, the decoder also unwraps opaque CMS SignedData and
     * returns its encapsulated MIME entity (signature verification remains a
     * separate concern handled by Thunderbird's normal message reader). */
    function unwrapCmsContent(body) {
      const input = Uint8Array.from(body, c => c.charCodeAt(0) & 0xff);
      const decoder = Cc[
        "@mozilla.org/nsCMSDecoderJS;1"
      ].createInstance(Ci.nsICMSDecoderJS);
      return byteArrayToString(decoder.decrypt(input));
    }

    /* Parse a decrypted MIME entity while asking MimeTreeEmitter to identify
     * attachments and retain their decoded bodies. getMimeTree() deliberately
     * uses the emitter's compatibility mode, which does not populate `name` or
     * `isAttachment`; those fields are required by walkDecryptedParts(). */
    function getAttachmentMimeTree(mimeString, notes) {
      const emitter = new MimeTreeEmitter({
        enableFilterMode: true,
        checkForAttachments: true,
      });
      try {
        const parser = new jsmime.MimeParser(emitter, {
          strformat: "unicode",
          bodyformat: "decode",
          stripcontinuations: false,
        });
        parser.deliverData(mimeString);
        return emitter.mimeTree.subParts[0] || null;
      } catch (e) {
        notes?.push(`attachment MIME parse failed: ${e}`);
        return null;
      }
    }

    /* Recursively gather the decrypted file attachments from a MimeTreePart. */
    function walkDecryptedParts(node, out) {
      if (!node) return;
      const ct = mimeContentType(node);
      const cd = (mimeHeader(node, "content-disposition") || "").toLowerCase();
      const cid = mimeHeader(node, "content-id");
      const name = mimeFilename(node);
      const isEnvelope =
        ct.includes("pkcs7-mime") ||
        ct.includes("enveloped-data") ||
        ct.includes("application/x-pkcs7-mime") ||
        name.toLowerCase().endsWith(".p7m") ||
        name.toLowerCase().endsWith(".p7s");

      const isNamedAttachment =
        !!name && (node.isAttachment || cd.includes("attachment"));
      if (!isEnvelope && typeof node.body === "string" && isNamedAttachment &&
          !(node.subParts && node.subParts.length) && !ct.includes("multipart/")) {
        const isInline =
          cd.includes("inline") ||
          (ct.startsWith("image/") && (cid || cd.includes("inline")));
        out.push({
          name,
          contentType: ct || "application/octet-stream",
          isInline: !!isInline,
          body: node.body,
        });
      }

      for (const c of node.subParts || []) walkDecryptedParts(c, out);
    }

    function runExtractDecryptedAttachments(messageUri) {
      const empty = { rows: [], log: [] };
      const logMsg = s => Services.console.logStringMessage(`[ForwardIntercept] extract: ${s}`);
      if (!messageUri) {
        logMsg("no messageUri");
        return Promise.resolve(empty);
      }

      return (async () => {
        const rows = [];
        const notes = [];
        try {
          // 1) Stream the RAW message bytes.
          const { ok, data } = await streamMessageToString(messageUri);
          if (!ok || !data) {
            notes.push(`raw stream not ok (len=${(data || "").length})`);
            logMsg(JSON.stringify(notes));
            return { rows, log: notes };
          }
          notes.push(`raw ${data.length} bytes`);

          // 2) Parse + decrypt the S/MIME envelope with Thunderbird's own
          //    MimeTreeDecrypter. It replaces the encrypted part's body with
          //    the decrypted content (a full signed rfc822 message) without
          //    re-parsing, so we take that body next.
          let root = getMimeTree(data, true);
          if (!root) {
            notes.push("getMimeTree(raw) returned null");
            logMsg(JSON.stringify(notes));
            return { rows, log: notes };
          }
          const decrypter = new MimeTreeDecrypter({ disablePrompts: true });
          await decrypter.decrypt(root);

          // Diagnostic: log the full tree after decryption so we can see how
          // jsmime structured the embedded rfc822 and where the decrypted body
          // actually landed.
          const treeSummary = [];
          (function dump(n, depth) {
            if (!n) return;
            treeSummary.push(
              " ".repeat(depth * 2) +
                (n.contentType || "?") +
                " | name=" + (n.name || "-") +
                " | body=" + (typeof n.body === "string" ? n.body.length : "none") +
                " | subs=" + ((n.subParts || []).length)
            );
            for (const c of n.subParts || []) dump(c, depth + 1);
          })(root, 0);
          notes.push("postDecryptTree=[" + treeSummary.join("; ") + "]");
          notes.push("decryptFailure=" + decrypter.decryptFailure + ", cryptoChanged=" + decrypter.cryptoChanged);

          let innerNode = null;
          /* decryptSMIME() splits the decrypted entity into headers and body:
           * it installs the inner Content-* headers on the encrypted tree node
           * and leaves only the payload in node.body. Reconstruct both pieces
           * before parsing again, otherwise a multipart body has no Content-Type
           * or boundary and getMimeTree() returns null. */
          if (decrypter.cryptoChanged && typeof root.body === "string" && root.body.length) {
            innerNode = root;
          } else {
            (function findDecrypted(node) {
              if (innerNode || !node) return;
              if ((node.fullContentType || "").toLowerCase().includes("pkcs7-mime") &&
                  typeof node.body === "string" && node.body.length) {
                innerNode = node;
                return;
              }
              for (const c of node.subParts || []) findDecrypted(c);
            })(root);
          }

          if (!innerNode) {
            notes.push("no decrypted body found (decryptFailure=" + decrypter.decryptFailure + ")");
            logMsg(JSON.stringify(notes));
            return { rows, log: notes };
          }
          const inner = mimeTreeToString(innerNode, true);
          notes.push(`decrypted entity ${inner.length} bytes (body=${innerNode.body.length})`);

          // 3) Re-parse the decrypted message and read attachment bodies.
          let decryptedTree = getAttachmentMimeTree(inner, notes);
          if (!decryptedTree) {
            notes.push("getAttachmentMimeTree(decrypted) returned null");
            logMsg(JSON.stringify(notes));
            return { rows, log: notes };
          }

          /* Encrypted-and-signed messages commonly contain an opaque
           * application/(x-)pkcs7-mime SignedData entity after the outer
           * EnvelopedData is decrypted. Descend through those CMS wrappers so
           * the final multipart/mixed tree (and its files) becomes visible. */
          for (let depth = 0; depth < 3; depth++) {
            const ct = mimeContentType(decryptedTree);
            if (!ct.includes("pkcs7-mime") || !decryptedTree.body) break;
            const unwrapped = unwrapCmsContent(decryptedTree.body);
            notes.push(`unwrapped CMS ${ct}: ${decryptedTree.body.length} -> ${unwrapped.length} bytes`);
            if (!unwrapped) break;
            decryptedTree = getAttachmentMimeTree(unwrapped, notes);
            if (!decryptedTree) break;
          }
          if (!decryptedTree) {
            notes.push("CMS payload MIME parse returned null");
            logMsg(JSON.stringify(notes));
            return { rows, log: notes };
          }
          const parts = [];
          walkDecryptedParts(decryptedTree, parts);
          notes.push(`${parts.length} exposed part(s)`);
          for (const p of parts) {
            notes.push(`candidate ${p.name} | ${p.contentType} | inline=${p.isInline} | body=${p.body ? p.body.length : 0}b`);
            if (p.isInline) continue;
            const b64 = bytesToBase64(p.body);
            if (b64) {
              rows.push({
                name: p.name,
                contentType: p.contentType,
                size: p.body.length,
                dataBase64: b64,
              });
              notes.push(`-> GOT bytes for ${p.name} (${rows[rows.length - 1].size}b)`);
            } else {
              notes.push(`-> NO BYTES for ${p.name}`);
            }
          }
        } catch (e) {
          notes.push(`extract failed: ${e}`);
        }
        logMsg(JSON.stringify(notes));
        return { rows, log: notes };
      })();
    }

    const sharedAPI = {
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

        async waitForRedirectedComposeReady(timeoutMs) {
          const ready = redirectComposeReady;
          if (!ready) return "unavailable";
          const timeout = new Promise(resolve => {
            setTimeout(() => resolve("timeout"), Math.max(0, timeoutMs));
          });
          return Promise.race([ready.promise, timeout]);
        },

        async extractDecryptedAttachments(messageUri) {
          return runExtractDecryptedAttachments(messageUri);
        },

        async getAndClearRedirectPending() {
          const pending = redirectPending;
          redirectPending = false;
          return pending;
        },
    };
    this._sharedAPI = sharedAPI;
    this._uninstallShared = uninstall;
    return {
      ForwardIntercept: sharedAPI,
    };
  }

  onShutdown(isAppShutdown) {
    try { this._uninstallShared?.(); } catch (_) {}
    this._sharedAPI = null;
    this._uninstallShared = null;
    if (!isAppShutdown) {
      Services.obs.notifyObservers(null, "startupcache-invalidate", null);
    }
  }
};
