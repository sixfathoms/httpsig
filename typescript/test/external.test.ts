import { describe, it, expect } from "vitest";
import { newHMACSHA256Key, verifyMessage } from "../src/index.js";
import type { HttpMessage } from "../src/index.js";

// The signatures below were computed with OpenSSL, not this library.
const key = newHMACSHA256Key("ext", Buffer.from("external-signer-shared-secret"));
const INPUT =
  '("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";x-ver=1.5;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000';
const SIG = "Ad8NkVPRZQqviyFbO8ThZYBK+4Wy5kmmPZvXP8n0wcE=";

function verify(input: string, sig: string) {
  const headers: Record<string, string> = {
    "signature-input": `sig1=${input}`,
    signature: `sig1=:${sig}:`,
  };
  const msg: HttpMessage = {
    isRequest: true,
    method: "GET",
    url: new URL("https://example.com/path"),
    headerValues: (name) => {
      const value = headers[name.toLowerCase()];
      return value === undefined ? [] : [value];
    },
  };
  return verifyMessage(msg, () => key, { now: () => 1700000010000 });
}

describe("signatures from other implementations", () => {
  it("verifies parameters in the sender's order", async () => {
    await expect(verify(INPUT, SIG)).resolves.toMatchObject({
      nonce: "n-1",
      created: 1700000000,
      expires: 4102444800,
    });
  });

  it.each([
    '("@method" "@authority" "@path");keyid="ext";tag="web-bot-auth";x-ver=1.5;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000',
    '("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000',
    '("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";x-ver=1.5;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000;extra=1',
    '("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";x-ver=1.6;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000',
  ])("rejects tampered parameters: %s", async (input) => {
    await expect(verify(input, SIG)).rejects.toThrow();
  });

  // Correctly signed, but a known parameter has the wrong type or value. Treating
  // it as absent would skip the checks that depend on it.
  it.each([
    ['tag="t";nonce=1', "VwvsdElH8JP3khcMIdq+JmXG221Un6uoWf50N+oqizY="],
    ['keyid="ext";alg=hmac-sha256', "aGPTGJuoa0VJSPmI75SNMl02fgIVE22uPJp7VB20r58="],
    ['keyid="ext";alg="nope"', "RFa0y6Ug/IP0hT5pxR2OtrOirbw2Up5r3M/aJ8Lq3a4="],
    ['keyid="ext";tag=1', "x3BJu6w8ENdN6a4FUxS0xlUb0uwiS3dsCmQQ+nplYnk="],
    ['keyid=ext', "HKzZMwFV7hsG2l1Kl2mjDhKYL9HrKbPckSY/lIxLN+g="],
  ])("rejects malformed parameter: %s", async (params, sig) => {
    await expect(verify(`("@method");${params}`, sig)).rejects.toThrow();
  });
});
