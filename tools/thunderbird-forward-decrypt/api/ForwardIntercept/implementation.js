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

    /* Best-effort detection of an embedded message/rfc822 container. The
     * forwarded message's own root Content-Type is what the forward composes
     * from; for an embedded S/MIME container that root is "message/rfc822".
     *
     * Signals inspected (any may be absent, so this is best-effort and we only
     * convert when we are fairly sure):
     *   o msgHdr.getStringProperty("Content-Type")
     *   o msgHdr.getStringProperty("contentType") / "ContentType"
     */
    function rootLooksEmbeddedContainer(msgHdr) {
      if (!msgHdr) {
        return false;
      }

      for (const name of [
        "Content-Type",
        "ContentType",
        "content-type",
        "contentType",
      ]) {
        try {
          const value = String(msgHdr.getStringProperty(name) || "")
            .trim()
            .toLowerCase();

          if (
            value === "message/rfc822" ||
            value.startsWith("message/rfc822;")
          ) {
            return true;
          }
        } catch (_) {}
      }

      return false;
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

      const wrapped = async function (...args) {
        Services.console.logStringMessage(
          `[ForwardIntercept] ComposeMessage CALLED type=${args[0]}`
        );
        const [type, format, folder, messageArray, selection, autodetectCharset] =
          args;
        try {
          if (
            enabled &&
            isForwardType(type) &&
            messageArray &&
            messageArray.length === 1
          ) {
            let hdr = null;

            try {
              hdr = win.messenger.msgHdrFromURI(messageArray[0]);
            } catch (_) {}

            if (rootLooksEmbeddedContainer(hdr)) {
              Services.console.logStringMessage(
                `[ForwardIntercept] redirect Forward -> Reply BEFORE compose window: ${messageArray[0]}`
              );

              type = COMPOSE_TYPE.ReplyToSender;
            }
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
      },
    };
  }
};