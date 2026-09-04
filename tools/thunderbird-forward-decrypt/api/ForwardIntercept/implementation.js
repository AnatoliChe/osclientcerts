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

var ForwardIntercept = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    /* Tracks whether we are intercepting. Default OFF; the background script
     * enables it (mirrors the v0.2.x "experiments" option so the code path is
     * inert unless explicitly turned on). */
    let enabled = false;

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
      },
    };
  }
};