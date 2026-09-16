const fs = require("fs");
const path = require("path");
const vm = require("vm");

function enumerator(items) {
  let index = 0;
  return {
    hasMoreElements: () => index < items.length,
    getNext: () => items[index++],
  };
}

function createWindow(href = "chrome://messenger/content/messenger.xhtml") {
  const listeners = new Map();
  const originalComposeMessage = jest.fn((...args) => args);
  const win = {
    closed: false,
    location: { href },
    ComposeMessage: originalComposeMessage,
    addEventListener: jest.fn((name, listener, options) => {
      listeners.set(name, { listener, options });
    }),
  };
  return {
    win,
    originalComposeMessage,
    dispatch(name) {
      const entry = listeners.get(name);
      if (!entry) throw new Error(`No listener registered for ${name}`);
      return entry.listener();
    },
    listener(name) {
      return listeners.get(name);
    },
  };
}

function loadExperiment(initialWindows = [], rawByUri = {}) {
  class ExtensionAPI {}
  const windowListener = { current: null };
  const logs = [];
  const Services = {
    console: { logStringMessage: jest.fn(message => logs.push(message)) },
    obs: { notifyObservers: jest.fn() },
    wm: {
      addListener: jest.fn(listener => { windowListener.current = listener; }),
      removeListener: jest.fn(),
      getEnumerator: jest.fn(() => enumerator(initialWindows.map(({ win }) => ({
        docShell: { domWindow: win },
      })))),
    },
  };
  const defaultRaw = [
    "Content-Type: message/rfc822",
    "",
    "Content-Type: application/pkcs7-mime; smime-type=enveloped-data",
  ].join("\r\n");
  const MailServices = {
    messageServiceFromURI: jest.fn(uri => ({
      streamMessage(_uri, listener) {
        const data = Object.prototype.hasOwnProperty.call(rawByUri, uri)
          ? rawByUri[uri]
          : defaultRaw;
        listener.onStartRequest();
        listener.onDataAvailable(null, { data }, 0, data.length);
        listener.onStopRequest(null, 0);
      },
    })),
  };
  const Cc = {
    "@mozilla.org/scriptableinputstream;1": {
      createInstance: () => ({
        init(input) { this.input = input; },
        read(count) { return this.input.data.slice(0, count); },
      }),
    },
  };
  const sandbox = {
    console,
    Promise,
    String,
    Uint8Array,
    File: class File {},
    Services,
    Cc,
    Ci: { nsIScriptableInputStream: Symbol("nsIScriptableInputStream") },
    Components: { isSuccessCode: status => status === 0 },
    ChromeUtils: {
      generateQI: jest.fn(() => jest.fn()),
      importESModule(uri) {
        if (uri.includes("ExtensionCommon")) return { ExtensionCommon: { ExtensionAPI } };
        if (uri.includes("Timer")) return { setTimeout };
        if (uri.includes("MailServices")) return { MailServices };
        if (uri.includes("MimeTree")) {
          return {
            MimeTreeDecrypter: class {},
            MimeTreeEmitter: class {},
            getMimeTree: jest.fn(data => {
              const rootType = /^content-type:\s*([^;\r\n]+)/im.exec(data)?.[1]
                ?.trim().toLowerCase() || "text/plain";
              const root = { contentType: rootType, fullContentType: rootType, subParts: [] };
              if (/application\/(?:x-)?pkcs7-mime[^\r\n]*enveloped-data/i.test(data)) {
                root.subParts.push({
                  contentType: "application/pkcs7-mime",
                  fullContentType: "application/pkcs7-mime; smime-type=enveloped-data",
                  subParts: [],
                });
              }
              return root;
            }),
            mimeTreeToString: jest.fn(),
          };
        }
        if (uri.includes("jsmime")) return { jsmime: {} };
        throw new Error(`Unexpected module: ${uri}`);
      },
    },
  };
  const source = fs.readFileSync(
    path.resolve(__dirname, "../api/ForwardIntercept/implementation.js"),
    "utf8",
  );
  vm.runInNewContext(source, sandbox, { filename: "implementation.js" });
  return { ForwardIntercept: sandbox.ForwardIntercept, Services, windowListener, logs };
}

describe("ForwardIntercept real lifecycle behaviour", () => {
  const flushAsyncForwardCheck = async () => {
    await new Promise(resolve => setImmediate(resolve));
  };
  test("startup wakes the MV3 background before the first Forward", async () => {
    const { ForwardIntercept } = loadExperiment();
    const wakeupBackground = jest.fn().mockResolvedValue(undefined);
    const experiment = new ForwardIntercept();
    experiment.extension = { wakeupBackground };

    await experiment.onStartup();

    expect(wakeupBackground).toHaveBeenCalledTimes(1);
  });

  test("one window is patched once and ordinary Reply is not redirected", async () => {
    const main = createWindow();
    const { ForwardIntercept, Services } = loadExperiment([main]);
    const experiment = new ForwardIntercept();
    const api = experiment.getAPI({}).ForwardIntercept;

    await api.setEnabled(true);
    const wrapper = main.win.ComposeMessage;
    await api.setEnabled(true);

    expect(main.win.ComposeMessage).toBe(wrapper);
    expect(Services.wm.addListener).toHaveBeenCalledTimes(1);
    main.win.ComposeMessage(6, 0, null, ["mailbox://reply"]);
    expect(main.originalComposeMessage).toHaveBeenLastCalledWith(
      6, 0, null, ["mailbox://reply"],
    );
    expect(await api.getAndClearRedirectPending()).toBe(false);
  });

  test("Forward marker survives recreation of the MV3 API context", async () => {
    const main = createWindow();
    const { ForwardIntercept } = loadExperiment([main]);
    const experiment = new ForwardIntercept();
    const firstContext = experiment.getAPI({}).ForwardIntercept;
    await firstContext.setEnabled(true);

    const header = {
      folder: { getUriForMsg: jest.fn(() => "mailbox://message/42") },
    };
    main.win.ComposeMessage(4, 0, null, [header]);
    await flushAsyncForwardCheck();

    expect(main.originalComposeMessage.mock.calls[0][0]).toBe(6);
    const secondContext = experiment.getAPI({}).ForwardIntercept;
    expect(secondContext).toBe(firstContext);
    expect(await secondContext.getLastForwardUri()).toBe("mailbox://message/42");
    expect(await secondContext.getAndClearRedirectPending()).toBe(true);
    expect(await secondContext.getAndClearRedirectPending()).toBe(false);
  });

  test("waits for ComposeBodyReady and observes a compose window closing", async () => {
    const main = createWindow();
    const compose = createWindow("chrome://messenger/content/messengercompose/messengercompose.xhtml");
    const stateListeners = [];
    compose.win.gMsgCompose = {
      RegisterStateListener: jest.fn(listener => stateListeners.push(listener)),
      UnregisterStateListener: jest.fn(),
    };
    const { ForwardIntercept, windowListener } = loadExperiment([main]);
    const experiment = new ForwardIntercept();
    const api = experiment.getAPI({}).ForwardIntercept;
    await api.setEnabled(true);
    main.win.ComposeMessage(4, 0, null, ["mailbox://message/42"]);
    await flushAsyncForwardCheck();

    windowListener.current.onOpenWindow({ docShell: { domWindow: compose.win } });
    expect(compose.listener("compose-window-init").options).toEqual(
      expect.objectContaining({ capture: true, once: true }),
    );
    compose.dispatch("compose-window-init");
    stateListeners[0].NotifyComposeBodyReady();
    await expect(api.waitForRedirectedComposeReady(100)).resolves.toBe("ready");

    main.win.ComposeMessage(4, 0, null, ["mailbox://message/43"]);
    await flushAsyncForwardCheck();
    const closedCompose = createWindow("chrome://messenger/content/messengercompose/messengercompose.xhtml");
    closedCompose.win.gMsgCompose = compose.win.gMsgCompose;
    windowListener.current.onOpenWindow({ docShell: { domWindow: closedCompose.win } });
    closedCompose.dispatch("compose-window-init");
    closedCompose.dispatch("unload");
    await expect(api.waitForRedirectedComposeReady(100)).resolves.toBe("closed");
  });

  test("ordinary message with an attachment keeps Thunderbird's normal Forward", async () => {
    const main = createWindow();
    const uri = "mailbox://message/plain-with-attachment";
    const ordinaryMessage = [
      "Content-Type: multipart/mixed; boundary=ordinary",
      "",
      "--ordinary",
      "Content-Type: text/plain",
      "",
      "hello",
      "--ordinary",
      "Content-Type: application/pdf",
      "Content-Disposition: attachment; filename=report.pdf",
    ].join("\r\n");
    const { ForwardIntercept } = loadExperiment([main], { [uri]: ordinaryMessage });
    const experiment = new ForwardIntercept();
    const api = experiment.getAPI({}).ForwardIntercept;
    await api.setEnabled(true);

    main.win.ComposeMessage(4, 0, null, [uri]);
    await flushAsyncForwardCheck();

    expect(main.originalComposeMessage).toHaveBeenCalledTimes(1);
    expect(main.originalComposeMessage.mock.calls[0][0]).toBe(4);
    expect(await api.getAndClearRedirectPending()).toBe(false);
  });

  test("top-level S/MIME uses normal Forward and is left to the background flow", async () => {
    const main = createWindow();
    const uri = "mailbox://message/top-level-smime";
    const topLevelSmime = [
      "Content-Type: application/pkcs7-mime; smime-type=enveloped-data",
      "",
      "encrypted payload",
    ].join("\r\n");
    const { ForwardIntercept } = loadExperiment([main], { [uri]: topLevelSmime });
    const experiment = new ForwardIntercept();
    const api = experiment.getAPI({}).ForwardIntercept;
    await api.setEnabled(true);

    main.win.ComposeMessage(4, 0, null, [uri]);
    await flushAsyncForwardCheck();

    expect(main.originalComposeMessage.mock.calls[0][0]).toBe(4);
    expect(await api.getAndClearRedirectPending()).toBe(false);
  });

  test("shutdown restores ComposeMessage and invalidates caches on addon reload", async () => {
    const main = createWindow();
    const { ForwardIntercept, Services } = loadExperiment([main]);
    const experiment = new ForwardIntercept();
    const api = experiment.getAPI({}).ForwardIntercept;
    await api.setEnabled(true);

    expect(main.win.ComposeMessage).not.toBe(main.originalComposeMessage);
    experiment.onShutdown(false);

    expect(main.win.ComposeMessage).toBe(main.originalComposeMessage);
    expect(Services.wm.removeListener).toHaveBeenCalledTimes(1);
    expect(Services.obs.notifyObservers).toHaveBeenCalledWith(
      null, "startupcache-invalidate", null,
    );
  });
});
