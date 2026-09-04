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
  });
});
