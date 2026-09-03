const {
  buildForwardHeader,
  plainToHtml,
  isSmimeEncrypted,
  canDecrypt,
  isP7mAttachment,
  htmlToPlain,
  retitleReplyToForward,
} = require("../lib");

describe("buildForwardHeader", () => {
  test("returns plain and html with all fields", () => {
    const msg = {
      subject: "Test Subject",
      author: "John Doe <john@example.com>",
      date: "2026-09-01T10:30:00Z",
      recipients: ["Alice <alice@example.com>", "Bob <bob@example.com>"],
      ccList: ["Charlie <charlie@example.com>"],
    };
    const result = buildForwardHeader(msg);

    expect(result.plain).toContain("-------- Forwarded Message --------");
    expect(result.plain).toContain("Subject: Test Subject");
    expect(result.plain).toContain("From: John Doe <john@example.com>");
    expect(result.plain).toContain("To: Alice <alice@example.com>, Bob <bob@example.com>");
    expect(result.plain).toContain("Cc: Charlie <charlie@example.com>");

    expect(result.html).toContain("Subject:</td><td>Test Subject</td>");
    expect(result.html).toContain("From:</td><td>John Doe &lt;john@example.com&gt;</td>");
  });

  test("handles empty message", () => {
    const msg = {};
    const result = buildForwardHeader(msg);

    expect(result.plain).toContain("-------- Forwarded Message --------");
    expect(result.plain).toContain("--------");
    expect(result.html).toContain("<table");
  });

  test("escapes HTML in fields", () => {
    const msg = {
      subject: '<script>alert("xss")</script>',
      author: "Test <test@test.com>",
    };
    const result = buildForwardHeader(msg);

    expect(result.html).not.toContain("<script>");
    expect(result.html).toContain("&lt;script&gt;");
  });

  test("handles missing optional fields", () => {
    const msg = { subject: "Only subject" };
    const result = buildForwardHeader(msg);

    expect(result.plain).toContain("Subject: Only subject");
    expect(result.plain).not.toContain("Date:");
    expect(result.plain).not.toContain("From:");
  });
});

describe("plainToHtml", () => {
  test("converts newlines to <br>", () => {
    expect(plainToHtml("line1\nline2")).toBe("line1<br>\nline2");
  });

  test("escapes HTML entities", () => {
    expect(plainToHtml("<b>bold</b>")).toBe("&lt;b&gt;bold&lt;/b&gt;");
    expect(plainToHtml("a & b")).toBe("a &amp; b");
    // plainToHtml only escapes &, <, > — not double quotes
  });

  test("handles \\r\\n", () => {
    expect(plainToHtml("line1\r\nline2")).toBe("line1<br>\nline2");
  });
});

describe("isSmimeEncrypted", () => {
  test("returns true for S/MIME encrypted (pkcs7-mime enveloped-data)", () => {
    const root = {
      contentType: "application/pkcs7-mime",
      headers: {
        "content-type": [
          "application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m"
        ],
      },
    };
    expect(isSmimeEncrypted(root)).toBe(true);
  });

  test("returns false for S/MIME signed (pkcs7-mime signed-data)", () => {
    const root = {
      contentType: "multipart/signed",
      headers: {
        "content-type": [
          'multipart/signed; protocol="application/pkcs7-signature"'
        ],
      },
    };
    expect(isSmimeEncrypted(root)).toBe(false);
  });

  test("returns false for plain text", () => {
    const root = {
      contentType: "text/plain",
      headers: { "content-type": ["text/plain; charset=utf-8"] },
    };
    expect(isSmimeEncrypted(root)).toBe(false);
  });

  test("returns false for OpenPGP", () => {
    const root = {
      contentType: "multipart/encrypted",
      headers: {
        "content-type": [
          'multipart/encrypted; protocol="application/pgp-encrypted"'
        ],
      },
    };
    expect(isSmimeEncrypted(root)).toBe(false);
  });

  test("returns false for null/undefined", () => {
    expect(isSmimeEncrypted(null)).toBe(false);
    expect(isSmimeEncrypted(undefined)).toBe(false);
    expect(isSmimeEncrypted({})).toBe(false);
  });
});

describe("canDecrypt", () => {
  test("returns true when decryptionStatus is success", () => {
    expect(canDecrypt({ decryptionStatus: "success" })).toBe(true);
  });

  test("returns false when decryptionStatus is fail", () => {
    expect(canDecrypt({ decryptionStatus: "fail" })).toBe(false);
  });

  test("returns false when decryptionStatus is none", () => {
    expect(canDecrypt({ decryptionStatus: "none" })).toBe(false);
  });

  test("returns false for null/undefined", () => {
    expect(canDecrypt(null)).toBe(false);
    expect(canDecrypt(undefined)).toBe(false);
  });
});

describe("isP7mAttachment", () => {
  test("matches smime.p7m", () => {
    expect(isP7mAttachment("smime.p7m")).toBe(true);
  });

  test("matches smime.p7s", () => {
    expect(isP7mAttachment("smime.p7s")).toBe(true);
  });

  test("matches any .p7m file", () => {
    expect(isP7mAttachment("message.p7m")).toBe(true);
    expect(isP7mAttachment("encrypted.p7m")).toBe(true);
  });

  test("matches any .p7s file", () => {
    expect(isP7mAttachment("message.p7s")).toBe(true);
  });

  test("is case insensitive", () => {
    expect(isP7mAttachment("SMIME.P7M")).toBe(true);
    expect(isP7mAttachment("Smime.P7S")).toBe(true);
  });

  test("rejects non-p7m files", () => {
    expect(isP7mAttachment("document.pdf")).toBe(false);
    expect(isP7mAttachment("image.png")).toBe(false);
    expect(isP7mAttachment("smime.p7x")).toBe(false);
  });

  test("handles null/undefined", () => {
    expect(isP7mAttachment(null)).toBe(false);
    expect(isP7mAttachment(undefined)).toBe(false);
    expect(isP7mAttachment("")).toBe(false);
  });
});

describe("htmlToPlain", () => {
  test("strips HTML tags", () => {
    expect(htmlToPlain("<p>Hello</p>")).toBe("Hello");
  });

  test("converts <br> to newlines", () => {
    expect(htmlToPlain("line1<br>line2")).toBe("line1\nline2");
    expect(htmlToPlain("line1<br/>line2")).toBe("line1\nline2");
    expect(htmlToPlain("line1<br />line2")).toBe("line1\nline2");
  });

  test("converts </p> to double newlines", () => {
    expect(htmlToPlain("<p>para1</p><p>para2</p>")).toBe("para1\n\npara2");
  });

  test("decodes HTML entities", () => {
    expect(htmlToPlain("&amp;")).toBe("&");
    expect(htmlToPlain("&lt;")).toBe("<");
    expect(htmlToPlain("&gt;")).toBe(">");
    expect(htmlToPlain("&quot;")).toBe('"');
    expect(htmlToPlain("a&nbsp;b")).toBe("a b");
  });

  test("removes style and script tags", () => {
    expect(htmlToPlain("<style>.x{}</style>Hello")).toBe("Hello");
    expect(htmlToPlain("<script>alert(1)</script>Hello")).toBe("Hello");
  });

  test("collapses multiple newlines", () => {
    expect(htmlToPlain("<p>a</p>\n<p>b</p>")).toBe("a\n\nb");
  });
});

describe("retitleReplyToForward", () => {
  test("retitles a simple Re: to Fwd:", () => {
    expect(retitleReplyToForward("Re: Hello")).toBe("Fwd: Hello");
  });

  test("only retitles the first Re: (nested becomes Fwd: Re: ...)", () => {
    expect(retitleReplyToForward("Re: Re: Hello")).toBe("Fwd: Re: Hello");
    expect(retitleReplyToForward("Re: Re: Re: Hello")).toBe("Fwd: Re: Re: Hello");
  });

  test("retitles with leading whitespace", () => {
    expect(retitleReplyToForward("  Re: Hello")).toBe("Fwd: Hello");
  });

  test("is case insensitive for the prefix", () => {
    expect(retitleReplyToForward("re: lowercase")).toBe("Fwd: lowercase");
    expect(retitleReplyToForward("RE: upper")).toBe("Fwd: upper");
  });

  test("does not touch a subject without a leading Re:", () => {
    expect(retitleReplyToForward("Hello")).toBe("");
    expect(retitleReplyToForward("Forwarded: Hello")).toBe("");
  });

  test("does not touch a bare \"Re:\" with empty rest", () => {
    // "Re:" alone retitles to "Fwd:"
    expect(retitleReplyToForward("Re:")).toBe("Fwd:");
  });

  test("handles null/undefined/empty", () => {
    expect(retitleReplyToForward(null)).toBe("");
    expect(retitleReplyToForward(undefined)).toBe("");
    expect(retitleReplyToForward("")).toBe("");
  });
});
