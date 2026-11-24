import type {
  Algorithm,
  ComponentIdentifier,
  HttpMessage,
  KeyProvider,
  SFVParams,
  SignatureParameters,
  SignatureRequirements,
  VerifyOptions,
  VerifyResult,
} from "./types.js";
import {
  InvalidSignatureError,
  MissingSignatureError,
  MalformedInputError,
} from "./errors.js";
import { parseDictionary, serializeComponentId, sfvParamsGet } from "./sfv.js";
import {
  buildSignatureBaseForVerification,
  parseComponents,
  requireInteger,
} from "./base.js";

/**
 * Verify a signature on a message.
 * Parses the Signature-Input and Signature headers, reconstructs the signature base,
 * and verifies using a key from the provider.
 */
export async function verifyMessage(
  msg: HttpMessage,
  provider: KeyProvider,
  opts?: VerifyOptions,
  reqMsg?: HttpMessage,
): Promise<VerifyResult> {
  const sigInputValues = msg.headerValues("signature-input");
  if (sigInputValues.length === 0) {
    throw new MissingSignatureError();
  }
  const sigInputStr = sigInputValues.join(", ");

  let sigInputDict;
  try {
    sigInputDict = parseDictionary(sigInputStr);
  } catch {
    throw new MalformedInputError("malformed Signature-Input header");
  }

  const sigValues = msg.headerValues("signature");
  if (sigValues.length === 0) {
    throw new MissingSignatureError();
  }
  const sigStr = sigValues.join(", ");

  let sigDict;
  try {
    sigDict = parseDictionary(sigStr);
  } catch {
    throw new MalformedInputError("malformed Signature header");
  }

  // Build lookup for signatures
  const sigMap = new Map<string, Uint8Array>();
  for (const m of sigDict) {
    if (m.item && m.item.value instanceof Uint8Array) {
      sigMap.set(m.key, m.item.value);
    }
  }

  // Try each signature input entry
  for (const member of sigInputDict) {
    const label = member.key;

    if (opts?.requiredLabel && label !== opts.requiredLabel) continue;
    if (!member.innerList) continue;

    let components: ComponentIdentifier[];
    try {
      components = parseComponents(member.innerList);
    } catch {
      continue;
    }

    let sigParams: SignatureParameters;
    try {
      sigParams = parseSignatureParams(
        member.innerList.params,
        components,
      );
    } catch {
      continue;
    }

    // Use requirements if set, otherwise fall back to requiredComponents
    if (opts?.requirements) {
      if (!matchesRequirements(sigParams, opts.requirements)) continue;
    } else if (
      opts?.requiredComponents &&
      !hasRequiredComponents(sigParams.components, opts.requiredComponents)
    ) {
      continue;
    }

    if (!checkTimeConstraints(sigParams, opts)) continue;

    const sigBytes = sigMap.get(label);
    if (!sigBytes) continue;

    let key;
    try {
      key = await provider(sigParams.keyId, sigParams.algorithm);
    } catch {
      continue;
    }

    // If algorithm was specified in the input, it must match the key
    if (sigParams.algorithm && key.algorithm !== sigParams.algorithm) {
      continue;
    }

    let base: Uint8Array;
    try {
      base = buildSignatureBaseForVerification(msg, member.innerList, reqMsg);
    } catch {
      continue;
    }

    let valid: boolean;
    try {
      valid = await key.verify(base, sigBytes);
    } catch {
      continue;
    }
    if (!valid) continue;

    if (opts?.nonceChecker && sigParams.nonce !== undefined) {
      await opts.nonceChecker(sigParams.nonce, key.keyId, key.algorithm);
    }

    return {
      label,
      keyId: key.keyId,
      algorithm: key.algorithm,
      components: sigParams.components,
      created: sigParams.created,
      expires: sigParams.expires,
      nonce: sigParams.nonce,
    };
  }

  throw new InvalidSignatureError();
}

function parseSignatureParams(
  params: SFVParams | undefined,
  components: ComponentIdentifier[],
): SignatureParameters {
  const sp: SignatureParameters = {
    components,
    keyId: "",
  };
  if (!params) return sp;

  const created = sfvParamsGet(params, "created");
  if (created !== undefined) sp.created = requireInteger("created", created);

  const expires = sfvParamsGet(params, "expires");
  if (expires !== undefined) sp.expires = requireInteger("expires", expires);

  sp.nonce = stringParam(params, "nonce");
  sp.algorithm = stringParam(params, "alg") as Algorithm | undefined;
  sp.keyId = stringParam(params, "keyid") ?? "";
  sp.tag = stringParam(params, "tag");

  return sp;
}

function stringParam(params: SFVParams, key: string): string | undefined {
  const value = sfvParamsGet(params, key);
  if (value !== undefined && typeof value !== "string") {
    throw new MalformedInputError(`${key} must be a string`);
  }
  return value;
}

function hasRequiredComponents(
  have: ComponentIdentifier[],
  required: ComponentIdentifier[],
): boolean {
  const haveSet = new Set(have.map(serializeComponentId));
  return required.every((c) => haveSet.has(serializeComponentId(c)));
}

function matchesRequirements(
  sigParams: SignatureParameters,
  req: SignatureRequirements,
): boolean {
  // Check required components
  if (
    req.components.length > 0 &&
    !hasRequiredComponents(sigParams.components, req.components)
  ) {
    return false;
  }
  // Check keyId
  if (req.keyId !== undefined && sigParams.keyId !== req.keyId) {
    return false;
  }
  // Check algorithm
  if (req.algorithm !== undefined && sigParams.algorithm !== req.algorithm) {
    return false;
  }
  // Check tag
  if (req.tag !== undefined && sigParams.tag !== req.tag) {
    return false;
  }
  return true;
}

function checkTimeConstraints(
  params: SignatureParameters,
  opts?: VerifyOptions,
): boolean {
  if (!opts) return true;

  const now = opts.now ? opts.now() : Date.now();

  if (params.created !== undefined && opts.maxAgeMs) {
    const createdMs = params.created * 1000;
    if (now - createdMs > opts.maxAgeMs) return false;
  }

  if (params.created !== undefined && opts.maxClockSkewMs) {
    const createdMs = params.created * 1000;
    if (createdMs - now > opts.maxClockSkewMs) return false;
  }

  const rejectExpired = opts.rejectExpired !== false;
  if (params.expires !== undefined && rejectExpired) {
    const expiresMs = params.expires * 1000;
    if (now > expiresMs) return false;
  }

  return true;
}
