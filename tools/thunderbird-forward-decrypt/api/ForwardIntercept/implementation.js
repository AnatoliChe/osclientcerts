/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * ForwardIntercept — privileged (parent) implementation.
 *
 * Wraps nsIMsgComposeService so that when the user triggers a *forward* of an
 * embedded message/rfc822 S/MIME container, the compose type is redirected to
 * a Reply BEFORE the compose window is created. This gives the user a single
 * reply window (with the full decrypted content) and no empty Forward-window
 * flash.
 *
 * Why a wrapper: the WebExtension compose API cannot intercept the Forward
 * button/menu/command — those dispatch through nsIMsgComposeService in the
 * main process. An Experiment runs in that same privileged scope, so it can
 * look at the actual forward request (the message being forwarded and its
 * type) and rewrite it to a reply.
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

    /* Compose-type constants (nsIMsgCompType). */
    const COMPOSE_TYPE = {
      New: 0,
      Reply: 1,
      ReplyAll: 2,
      ForwardAsAttachment: 3,
      ForwardInline: 4,
      NewsPost: 5,
      ReplyToSender: 6,
      ReplyToGroup: 7,
      ReplyToSenderAndGroup: 8,
      Draft: 9,
      Template: 10,
      MailToUrl: 11,
      ReplyWithTemplate: 12,
      ReplyToList: 13,
      Redirect: 14,
      EditAsNew: 15,
      EditTemplate: 16,
    };

    function isForwardType(t) {
      return (
        t === COMPOSE_TYPE.ForwardAsAttachment ||
        t === COMPOSE_TYPE.ForwardInline
      );
    }

    /* Best-effort detection of an embedded message/rfc822 container. The
     * forwarded message's own root Content-Type is what the forward composes
     * from; for an S/MIME container that root is "message/rfc822".
     *
     * Signals inspected (any may be absent, so this is best-effort; the
     * wrapper stays conservative and only converts when we are fairly sure):
     *   o msgHdr.getStringProperty("Content-Type")
     *   o msgHdr.getStringProperty("contentType") / "ContentType"
     */
    function rootLooksEmbeddedContainer(msgHdr) {
      try {
        if (!msgHdr) return false;
        const candidates = [
          "Content-Type",
          "ContentType",
          "content-type",
          "contentType",
        ];
        for (const k of candidates) {
          let ct = "";
          try {
            ct = (msgHdr.getStringProperty(k) || "").trim().toLowerCase();
          } catch (_) {
            continue;
          }
          if (!ct) continue;
          if (ct === "message/rfc822") return true;
          if (ct.startsWith("message/rfc822;")) return true;
        }
      } catch (e) {
        try { Services.console.logStringMessage(`[ForwardIntercept] detect error: ${e}`); } catch (_) {}
      }
      return false;
    }

    /* Store the wrapped originals so QI/equality is preserved and we can
     * restore them on disable. */
    let origOpenComposeWindow = null;
    let origOpenComposeWindowWithParams = null;

    /* Wrap an OpenComposeWindow call with type-based redirection.
     * Signature (from nsIMsgComposeService.idl):
     *   OpenComposeWindow(msgComposeWindowURL, msgHdr, originalMsgURI, type,
     *                     format, identity, from, aMsgWindow, [selectionHTML],
     *                     [autodetectCharset])
     */
    function wrappedOpenComposeWindow() {
      const args = Array.from(arguments);
      const type = args[3];
      const msgHdr = args[1];
      const originalMsgURI = args[2];

      if (enabled && isForwardType(type) && rootLooksEmbeddedContainer(msgHdr)) {
        const newType = COMPOSE_TYPE.ReplyToSender;
        args[3] = newType;
        Services.console.logStringMessage(
          `[ForwardIntercept] redirecting forward (type=${type}) -> reply (type=${newType}) for embedded container "${originalMsgURI}"`
        );
        return origOpenComposeWindow.apply(null, args);
      }
      return origOpenComposeWindow.apply(null, args);
    }

    /* Wrap OpenComposeWindowWithParams (the path compose commands commonly use
     * via ComposeMessageInTabOrWindow). The type lives on the params object. */
    function wrappedOpenComposeWindowWithParams() {
      const args = Array.from(arguments);
      const params = args[1];
      if (enabled && params) {
        let currentType = -1;
        try { currentType = params.type; } catch (_) {}
        if (isForwardType(currentType)) {
          /* Try to inspect the message header for an embedded container. */
          let msgHdr = null;
          try { msgHdr = params.origMsgHdr; } catch (_) {}
          if (!msgHdr) {
            /* Fall back to compFields/originalMsgURI if header is not exposed. */
          }
          if (rootLooksEmbeddedContainer(msgHdr)) {
            const newType = COMPOSE_TYPE.ReplyToSender;
            try { params.type = newType; } catch (e) {
              Services.console.logStringMessage(`[ForwardIntercept] could not set params.type: ${e}`);
            }
            Services.console.logStringMessage(
              `[ForwardIntercept][params] redirecting forward (type=${currentType}) -> reply (type=${newType})`
            );
          }
        }
      }
      return origOpenComposeWindowWithParams.apply(this, args);
    }

    /* Install / remove the wrappers on the compose service singleton. */
    function install() {
      const composeService = Cc["@mozilla.org/messengercompose;1"]
        .createInstance(Ci.nsIMsgComposeService);
      if (!composeService) {
        Services.console.logStringMessage("[ForwardIntercept] compose service not available");
        return false;
      }
      if (origOpenComposeWindow == null) {
        origOpenComposeWindow = composeService.OpenComposeWindow.bind(composeService);
      }
      if (origOpenComposeWindowWithParams == null) {
        origOpenComposeWindowWithParams = composeService.OpenComposeWindowWithParams.bind(composeService);
      }
      /* Reassignment on the XPCOM instance is honored for scriptable methods;
       * we store the wrapped bound functions so `this` stays the service.
       * TEST: confirm the assignment actually took effect (on some build the
       * methods are read-only on the interface object). */
      const before = composeService.OpenComposeWindow;
      composeService.OpenComposeWindow = wrappedOpenComposeWindow;
      composeService.OpenComposeWindowWithParams = wrappedOpenComposeWindowWithParams;
      const patched =
        composeService.OpenComposeWindow === wrappedOpenComposeWindow &&
        composeService.OpenComposeWindowWithParams === wrappedOpenComposeWindowWithParams;
      Services.console.logStringMessage(
        `[ForwardIntercept] compose service wrapped; patch APPLIED=${patched}` +
          (patched ? "" : ` (before identity preserved: ${composeService.OpenComposeWindow === before})`)
      );
      return true;
    }

    function uninstall() {
      try {
        const composeService = Cc["@mozilla.org/messengercompose;1"]
          .createInstance(Ci.nsIMsgComposeService);
        if (origOpenComposeWindow) composeService.OpenComposeWindow = origOpenComposeWindow;
        if (origOpenComposeWindowWithParams) composeService.OpenComposeWindowWithParams = origOpenComposeWindowWithParams;
        Services.console.logStringMessage("[ForwardIntercept] compose service unwrapped");
      } catch (e) {
        Services.console.logStringMessage(`[ForwardIntercept] uninstall error: ${e}`);
      }
    }

    return {
      ForwardIntercept: {
        async getEnabled() {
          return enabled;
        },
        async setEnabled(newEnabled) {
          if (!!newEnabled !== enabled) {
            const ok = !!newEnabled ? install() : uninstall();
            if (!!newEnabled && !ok) return false;
            enabled = !!newEnabled;
          }
          return enabled;
        },
      },
    };
  }
};