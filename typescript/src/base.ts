import type {
  ComponentIdentifier,
  HttpMessage,
  SignatureParameters,
  SFVInnerList,
  SFVParams,
} from "./types.js";
import { DuplicateComponentError, MalformedInputError } from "./errors.js";
import {
  newSFVParams,
  sfvParamsSet,
  serializeComponentId,
  serializeInnerList,
  serializeSignatureParams,
} from "./sfv.js";
import { extractComponent } from "./components.js";

/**
 * Build the signature base string per RFC 9421 Section 2.5.
 * Returns [signatureBase, signatureParamsValue].
 */
export function buildSignatureBase(
  msg: HttpMessage,
  params: SignatureParameters,
  reqMsg?: HttpMessage,
): [Uint8Array, string] {
  const sigParamsValue = serializeSignatureParams(
    params.components,
    buildSFVParams(params),
  );
  return [
    buildBase(params.components, sigParamsValue, msg, reqMsg),
    sigParamsValue,
  ];
}

/**
 * Build the signature base for verifying a received signature. The inner list
 * is the parsed Signature-Input member: the signature covers its parameters in
 * the order the sender wrote them.
 */
export function buildSignatureBaseForVerification(
  msg: HttpMessage,
  innerList: SFVInnerList,
  reqMsg?: HttpMessage,
): Uint8Array {
  return buildBase(
    parseComponents(innerList),
    serializeInnerList(innerList),
    msg,
    reqMsg,
  );
}

export function parseComponents(innerList: SFVInnerList): ComponentIdentifier[] {
  return innerList.items.map(({ value, params }) => {
    if (typeof value !== "string") {
      throw new MalformedInputError("component identifier must be a string");
    }
    return { name: value, params };
  });
}

function buildBase(
  components: ComponentIdentifier[],
  sigParamsValue: string,
  msg: HttpMessage,
  reqMsg?: HttpMessage,
): Uint8Array {
  validateComponents(components);
  let base = "";
  for (const c of components) {
    const value = extractComponent(c, msg, reqMsg);
    base += serializeComponentId(c) + ": " + value + "\n";
  }
  base += '"@signature-params": ' + sigParamsValue;
  return new TextEncoder().encode(base);
}

function buildSFVParams(params: SignatureParameters): SFVParams {
  let p = newSFVParams();
  if (params.created !== undefined) {
    p = sfvParamsSet(p, "created", requireInteger("created", params.created));
  }
  if (params.expires !== undefined) {
    p = sfvParamsSet(p, "expires", requireInteger("expires", params.expires));
  }
  if (params.keyId) {
    p = sfvParamsSet(p, "keyid", params.keyId);
  }
  if (params.algorithm) {
    p = sfvParamsSet(p, "alg", params.algorithm);
  }
  if (params.nonce !== undefined) {
    p = sfvParamsSet(p, "nonce", params.nonce);
  }
  if (params.tag !== undefined) {
    p = sfvParamsSet(p, "tag", params.tag);
  }
  return p;
}

/** Signature timestamps are SFV Integers; Decimals are not allowed (RFC 9421 Section 2.3). */
export function requireInteger(name: string, value: unknown): number {
  if (!Number.isInteger(value)) {
    throw new MalformedInputError(`${name} must be an integer`);
  }
  return value as number;
}

function validateComponents(components: ComponentIdentifier[]): void {
  const seen = new Set<string>();
  for (const c of components) {
    const key = serializeComponentId(c);
    if (seen.has(key)) {
      throw new DuplicateComponentError(key);
    }
    seen.add(key);
  }
}
