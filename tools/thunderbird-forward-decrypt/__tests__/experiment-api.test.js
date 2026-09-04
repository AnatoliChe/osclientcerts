const fs = require("fs");
const path = require("path");

describe("ForwardIntercept experiment API contract", () => {
  const addonDir = path.resolve(__dirname, "..");
  const manifest = JSON.parse(
    fs.readFileSync(path.join(addonDir, "manifest.json"), "utf8"),
  );
  const schema = JSON.parse(
    fs.readFileSync(
      path.join(addonDir, "api", "ForwardIntercept", "schema.json"),
      "utf8",
    ),
  );
  const background = fs.readFileSync(
    path.join(addonDir, "background.js"),
    "utf8",
  );
  const implementation = fs.readFileSync(
    path.join(addonDir, "api", "ForwardIntercept", "implementation.js"),
    "utf8",
  );

  test("redirect marker is exposed asynchronously under the registered namespace", () => {
    const namespace = schema[0].namespace;
    const markerFunction = schema[0].functions.find(
      entry => entry.name === "getAndClearRedirectPending",
    );

    expect(namespace).toBe("ForwardIntercept");
    expect(manifest.experiment_apis).toHaveProperty(namespace);
    expect(markerFunction).toEqual(
      expect.objectContaining({ type: "function", async: true }),
    );
    expect(background).toContain(`const fi = browser.${namespace}`);
    expect(background).toContain("fi.getAndClearRedirectPending()");
    expect(background).not.toContain("browser.forwardIntercept");
  });

  test("reconstructs decrypted MIME headers and enables attachment discovery", () => {
    expect(implementation).toContain("mimeTreeToString(innerNode, true)");
    expect(implementation).toContain("enableFilterMode: true");
    expect(implementation).toContain("checkForAttachments: true");
    expect(implementation).toContain("unwrapCmsContent(decryptedTree.body)");
    expect(implementation).toContain("const isNamedAttachment =");
    expect(implementation).not.toContain('ct !== "text/plain"');
    expect(implementation).not.toContain('typeof btoa !== "function"');
    expect(implementation).toContain("size: p.body.length");
  });

  test("waits for real compose body readiness instead of a fixed delay", () => {
    const readinessFunction = schema[0].functions.find(
      entry => entry.name === "waitForRedirectedComposeReady",
    );
    expect(readinessFunction).toEqual(
      expect.objectContaining({ type: "function", async: true }),
    );
    expect(implementation).toContain("NotifyComposeBodyReady()");
    expect(implementation).toContain('ready.resolve("closed")');
    expect(implementation).toContain('"resource://gre/modules/Timer.sys.mjs"');
    expect(background).toContain("waitForRedirectedComposeReady(8000)");
    expect(implementation).toContain("{ capture: true, once: true }");
    const handler = background.slice(
      background.indexOf("async function handleExperimentReplyTab"),
      background.indexOf("async function processComposeTab"),
    );
    expect(handler).not.toContain("await sleep(3000)");
    expect(handler).toContain("closedTabIds.has(tabId)");
  });

  test("always enables the supported intercept path and exposes no experiment toggle", () => {
    const optionsHtml = fs.readFileSync(path.join(addonDir, "options.html"), "utf8");
    const optionsJs = fs.readFileSync(path.join(addonDir, "options.js"), "utf8");
    expect(background).toContain("browser.ForwardIntercept.setEnabled(true)");
    expect(background).not.toContain("experimentsEnabled");
    expect(optionsHtml).not.toContain('id="experiments"');
    expect(optionsJs).not.toContain("experiments");
    expect(background).not.toContain("handleEmbeddedForward(tabId, relatedMessageId");
  });
});
