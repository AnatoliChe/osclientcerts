/**
 * Integration tests for the forward-decrypt flow.
 * Mocks browser.* APIs and tests the full detection → rebuild pipeline.
 */

const { buildForwardHeader, isSmimeEncrypted, canDecrypt, isP7mAttachment } = require("../lib");

/* ---- Global browser mock ---- */
function createMockBrowser() {
  const listeners = { tabs: {}, compose: {} };

  const browser = {
    messages: {
      getFull: jest.fn(),
      get: jest.fn(),
      listInlineTextParts: jest.fn(),
      listAttachments: jest.fn(),
      getAttachmentFile: jest.fn(),
    },
    compose: {
      getComposeDetails: jest.fn(),
      setComposeDetails: jest.fn(),
      listAttachments: jest.fn(),
      removeAttachment: jest.fn(),
      addAttachment: jest.fn(),
      onAttachmentAdded: {
        addListener: jest.fn(),
      },
    },
    tabs: {
      onCreated: {
        addListener: jest.fn((fn) => { listeners.tabs.onCreated = fn; }),
      },
      onRemoved: {
        addListener: jest.fn(),
      },
      query: jest.fn(),
    },
  };

  return { browser, listeners };
}

/* ---- Simulate the core flow from processComposeTab ---- */
async function simulateProcessComposeTab(browser, tabId, details, msgRoot, decryptedParts, decryptedAtts) {
  // waitForComposeDetails returns details
  browser.compose.getComposeDetails.mockResolvedValue(details);

  // isSmimeEncrypted check
  browser.messages.getFull.mockImplementation((id, opts) => {
    if (opts && opts.decrypt === false) return Promise.resolve(msgRoot);
    // canDecrypt check (default decrypt)
    return Promise.resolve({ decryptionStatus: "success" });
  });

  // messages.get for header
  browser.messages.get.mockResolvedValue({
    subject: "Fwd: Test",
    author: "sender@example.com",
    date: "2026-09-01T10:00:00Z",
    recipients: ["recipient@example.com"],
    ccList: [],
  });

  // listInlineTextParts
  browser.messages.listInlineTextParts.mockResolvedValue(decryptedParts);

  // listAttachments (decrypted)
  browser.messages.listAttachments.mockResolvedValue(decryptedAtts);

  // getAttachmentFile
  browser.messages.getAttachmentFile.mockResolvedValue({ name: "file.bin" });

  // compose.listAttachments (current compose attachments - has smime.p7m)
  browser.compose.listAttachments.mockResolvedValue([
    { id: 1, name: "smime.p7m", size: 1234 },
  ]);

  browser.compose.setComposeDetails.mockResolvedValue();
  browser.compose.removeAttachment.mockResolvedValue();
  browser.compose.addAttachment.mockResolvedValue();

  // Now run the logic
  if (details.type !== "forward") return { processed: false, reason: "not-forward" };
  const relatedMessageId = details.relatedMessageId;
  if (!relatedMessageId) return { processed: false, reason: "no-related-id" };

  const raw = await browser.messages.getFull(relatedMessageId, { decrypt: false });
  if (!isSmimeEncrypted(raw)) return { processed: false, reason: "not-smime-encrypted" };

  const full = await browser.messages.getFull(relatedMessageId);
  if (!canDecrypt(full)) return { processed: false, reason: "cannot-decrypt" };

  // Rebuild
  const msgHeader = await browser.messages.get(relatedMessageId);
  const { plain: headerPlain, html: headerHtml } = buildForwardHeader(msgHeader);

  const parts = await browser.messages.listInlineTextParts(relatedMessageId);
  let plainPart = null, htmlPart = null;
  for (const p of parts) {
    if (p.contentType === "text/plain" && !plainPart) plainPart = p;
    if (p.contentType === "text/html" && !htmlPart) htmlPart = p;
  }

  const isPlainText = details.isPlainText === true;
  let newPlainBody = null, newHtmlBody = null;

  if (isPlainText) {
    let content = plainPart ? plainPart.content : "";
    newPlainBody = headerPlain + (content ? "\n\n" + content : "");
  } else {
    let content = htmlPart ? htmlPart.content : "";
    newHtmlBody = headerHtml + (content ? "<br><br>" + content : "");
  }

  // Remove smime attachments
  const attachments = await browser.compose.listAttachments(1);
  for (const att of attachments) {
    if (isP7mAttachment(att.name)) {
      await browser.compose.removeAttachment(1, att.id);
    }
  }

  // Set body + encryption
  const updateDetails = {};
  if (isPlainText) updateDetails.plainTextBody = newPlainBody;
  else updateDetails.body = newHtmlBody;
  updateDetails.selectedEncryptionTechnology = {
    name: "S/MIME", encryptBody: true, signMessage: true,
  };
  await browser.compose.setComposeDetails(1, updateDetails);

  // Add decrypted attachments
  const decAtts = await browser.messages.listAttachments(relatedMessageId);
  for (const att of decAtts) {
    if (att.contentDisposition === "inline" && att.contentType && att.contentType.startsWith("image/")) continue;
    const file = await browser.messages.getAttachmentFile(relatedMessageId, att.partName);
    await browser.compose.addAttachment(1, { file, name: att.name || file.name });
  }

  return { processed: true, isPlainText };
}

/* ---- Tests ---- */
describe("Full flow: forward of S/MIME encrypted message", () => {
  let mock;

  beforeEach(() => {
    mock = createMockBrowser();
  });

  test("rebuilds HTML compose with decrypted body", async () => {
    const result = await simulateProcessComposeTab(
      mock.browser, 1,
      { type: "forward", relatedMessageId: 42, isPlainText: false },
      { contentType: "application/pkcs7-mime", headers: { "content-type": ["application/pkcs7-mime; smime-type=enveloped-data"] } },
      [{ contentType: "text/html", content: "<p>Hello World</p>" }],
      [],
    );

    expect(result.processed).toBe(true);
    expect(result.isPlainText).toBe(false);

    // Body should contain decrypted content
    const call = mock.browser.compose.setComposeDetails.mock.calls[0];
    expect(call[1].body).toContain("<p>Hello World</p>");
    expect(call[1].body).toContain("Subject:");
    expect(call[1].selectedEncryptionTechnology).toEqual({
      name: "S/MIME", encryptBody: true, signMessage: true,
    });

    // smime.p7m should be removed
    expect(mock.browser.compose.removeAttachment).toHaveBeenCalledWith(1, 1);
  });

  test("rebuilds plain-text compose", async () => {
    const result = await simulateProcessComposeTab(
      mock.browser, 1,
      { type: "forward", relatedMessageId: 42, isPlainText: true },
      { contentType: "application/pkcs7-mime", headers: { "content-type": ["application/pkcs7-mime; smime-type=enveloped-data"] } },
      [{ contentType: "text/plain", content: "Hello World" }],
      [],
    );

    expect(result.processed).toBe(true);
    expect(result.isPlainText).toBe(true);

    const call = mock.browser.compose.setComposeDetails.mock.calls[0];
    expect(call[1].plainTextBody).toContain("Hello World");
    expect(call[1].plainTextBody).toContain("Forwarded Message");
  });

  test("adds decrypted file attachments", async () => {
    const result = await simulateProcessComposeTab(
      mock.browser, 1,
      { type: "forward", relatedMessageId: 42, isPlainText: false },
      { contentType: "application/pkcs7-mime", headers: { "content-type": ["application/pkcs7-mime; smime-type=enveloped-data"] } },
      [{ contentType: "text/html", content: "<p>Body</p>" }],
      [
        { name: "report.pdf", partName: "2", contentDisposition: "attachment", contentType: "application/pdf" },
        { name: "data.xlsx", partName: "3", contentDisposition: "attachment", contentType: "application/vnd.ms-excel" },
      ],
    );

    expect(result.processed).toBe(true);
    expect(mock.browser.compose.addAttachment).toHaveBeenCalledTimes(2);
    expect(mock.browser.compose.addAttachment).toHaveBeenCalledWith(1, expect.objectContaining({ name: "report.pdf" }));
    expect(mock.browser.compose.addAttachment).toHaveBeenCalledWith(1, expect.objectContaining({ name: "data.xlsx" }));
  });

  test("skips inline image attachments", async () => {
    const result = await simulateProcessComposeTab(
      mock.browser, 1,
      { type: "forward", relatedMessageId: 42, isPlainText: false },
      { contentType: "application/pkcs7-mime", headers: { "content-type": ["application/pkcs7-mime; smime-type=enveloped-data"] } },
      [{ contentType: "text/html", content: '<p>Hi</p><img src="cid:logo.png">' }],
      [
        { name: "logo.png", partName: "2", contentDisposition: "inline", contentType: "image/png" },
        { name: "doc.pdf", partName: "3", contentDisposition: "attachment", contentType: "application/pdf" },
      ],
    );

    expect(result.processed).toBe(true);
    expect(mock.browser.compose.addAttachment).toHaveBeenCalledTimes(1);
    expect(mock.browser.compose.addAttachment).toHaveBeenCalledWith(1, expect.objectContaining({ name: "doc.pdf" }));
  });
});

describe("Full flow: non-forward compose", () => {
  let mock;

  beforeEach(() => {
    mock = createMockBrowser();
  });

  test("skips reply", async () => {
    const result = await simulateProcessComposeTab(
      mock.browser, 1,
      { type: "reply", relatedMessageId: 42, isPlainText: false },
      null, [], [],
    );

    expect(result.processed).toBe(false);
    expect(result.reason).toBe("not-forward");
  });

  test("skips new message", async () => {
    const result = await simulateProcessComposeTab(
      mock.browser, 1,
      { type: "new", isPlainText: false },
      null, [], [],
    );

    expect(result.processed).toBe(false);
    expect(result.reason).toBe("not-forward");
  });
});

describe("Full flow: forward without relatedMessageId", () => {
  let mock;

  beforeEach(() => {
    mock = createMockBrowser();
  });

  test("skips forward from file", async () => {
    const result = await simulateProcessComposeTab(
      mock.browser, 1,
      { type: "forward", relatedMessageId: undefined, isPlainText: false },
      null, [], [],
    );

    expect(result.processed).toBe(false);
    expect(result.reason).toBe("no-related-id");
  });
});

describe("Full flow: non-S/MIME message", () => {
  let mock;

  beforeEach(() => {
    mock = createMockBrowser();
  });

  test("skips plain text message", async () => {
    mock.browser.messages.getFull.mockResolvedValue({
      contentType: "text/plain",
      headers: { "content-type": ["text/plain"] },
    });

    const result = await simulateProcessComposeTab(
      mock.browser, 1,
      { type: "forward", relatedMessageId: 42, isPlainText: false },
      { contentType: "text/plain", headers: { "content-type": ["text/plain"] } },
      [],
      [],
    );

    expect(result.processed).toBe(false);
    expect(result.reason).toBe("not-smime-encrypted");
  });
});
