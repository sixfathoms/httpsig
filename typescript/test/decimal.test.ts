import { describe, it, expect } from "vitest";
import {
  SFVDecimal,
  component,
  componentWithKey,
  extractComponent,
  newHMACSHA256Key,
  parseDictionary,
  serializeBareItem,
  signMessage,
  signatureHeader,
  signatureInputHeader,
  verifyMessage,
} from "../src/index.js";
import type { HttpMessage } from "../src/index.js";

function makeRequest(headers: Record<string, string>): HttpMessage {
  return {
    isRequest: true,
    method: "GET",
    url: new URL("https://example.com/"),
    headerValues: (name) => {
      const value = headers[name.toLowerCase()];
      return value === undefined ? [] : [value];
    },
  };
}

describe("SFV decimals", () => {
  it.each([
    ["1.0", "1.0"],
    ["1.50", "1.5"],
    ["1.500", "1.5"],
    ["0.001", "0.001"],
    ["10.010", "10.01"],
    ["100.0", "100.0"],
    ["-1.5", "-1.5"],
    ["-0.5", "-0.5"],
    ["-0.0", "0.0"],
    ["00.5", "0.5"],
    ["999999999999.999", "999999999999.999"],
    ["-999999999999.999", "-999999999999.999"],
    ["1.5;q=0.50", "1.5;q=0.5"],
    ["(1.50 2.0);q=0.250", "(1.5 2.0);q=0.25"],
    ["1", "1"],
  ])("round-trips %s through ;key as %s", (input, want) => {
    const msg = makeRequest({ dict: `a=${input}` });
    expect(extractComponent(componentWithKey("dict", "a"), msg)).toBe(want);
  });

  it.each(["1.", "1.2345", "1.0000", "1234567890123.0", "0000000000001.0", "-.5", ".5", "-", "1.-5", "1.;q=1"])(
    "rejects %s",
    (input) => {
      expect(() => parseDictionary(`a=${input}`)).toThrow();
    },
  );

  it("keeps integers and decimals distinct", () => {
    const [a, b] = parseDictionary("a=1, b=1.0");
    expect(a.item?.value).toBe(1);
    expect(b.item?.value).toEqual(new SFVDecimal(1));
  });

  it.each([
    [1, "1.0"],
    [0.0625, "0.062"],
    [0.1875, "0.188"],
    [-0.0625, "-0.062"],
    [0.0004, "0.0"],
    [-0.0004, "0.0"],
    [1e-7, "0.0"],
    [999999999999.999, "999999999999.999"],
  ])("rounds %d to %s", (input, want) => {
    expect(new SFVDecimal(input).toString()).toBe(want);
  });

  it.each([1e12, -1e12, 1e300, 999999999999.9999, NaN, Infinity])(
    "rejects out-of-range %d",
    (input) => {
      expect(() => new SFVDecimal(input)).toThrow(RangeError);
    },
  );

  it("serializes every thousandth of a large value exactly", () => {
    for (let i = 0; i < 1000; i++) {
      const text = `999999999998.${String(i).padStart(3, "0")}`;
      const want = text.replace(/0+$/, "").replace(/\.$/, ".0");
      expect(new SFVDecimal(Number(text)).toString()).toBe(want);
    }
  });

  it("serializes fractional numbers as decimals", () => {
    expect(serializeBareItem(1.5)).toBe("1.5");
    expect(serializeBareItem(1e-7)).toBe("0.0");
  });
});

describe("non-integer timestamps", () => {
  const key = newHMACSHA256Key("k", Buffer.from("decimal-timestamp-test-secret"));
  const params = { components: [component("@method")], keyId: "k" };

  it.each([
    ["", true],
    [";created=1.5", false],
    [";expires=1.0", false],
    [';created="1"', false],
  ])("verifying with suffix '%s' succeeds: %s", async (suffix, ok) => {
    const result = await signMessage(makeRequest({}), "sig1", params, key);
    const msg = makeRequest({
      "signature-input": signatureInputHeader(result) + suffix,
      signature: signatureHeader(result),
    });
    const verified = verifyMessage(msg, () => key);
    if (ok) await expect(verified).resolves.toBeDefined();
    else await expect(verified).rejects.toThrow();
  });

  it("refuses to sign", async () => {
    await expect(
      signMessage(makeRequest({}), "sig1", { ...params, created: 1.5 }, key),
    ).rejects.toThrow("created must be an integer");
  });
});
