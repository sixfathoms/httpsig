/** Signature algorithm identifiers per RFC 9421 Section 3.3. */
export type Algorithm =
  | "rsa-pss-sha256"
  | "rsa-pss-sha384"
  | "rsa-pss-sha512"
  | "rsa-v1_5-sha256"
  | "ecdsa-p256-sha256"
  | "ecdsa-p384-sha384"
  | "ecdsa-p521-sha512"
  | "ed25519"
  | "hmac-sha256"
  | "hmac-sha384"
  | "hmac-sha512";

/** Digest algorithm identifiers per RFC 9530. */
export type DigestAlgorithm = "sha-256" | "sha-512";

/** Ordered key-value parameter map for SFV. */
export interface SFVParams {
  readonly keys: string[];
  readonly values: Record<string, SFVBareItem>;
}

/**
 * SFV bare item. A parsed Integer is a number and a parsed Decimal is an
 * SFVDecimal, so that Integer 1 and Decimal 1.0 stay distinct.
 */
export type SFVBareItem =
  | string
  | number
  | boolean
  | Uint8Array
  | SFVToken
  | SFVDecimal;

/** Wrapper to distinguish tokens from strings in SFV serialization. */
export class SFVToken {
  constructor(public readonly value: string) {}
}

/**
 * An SFV Decimal (RFC 8941 Section 3.3.2): up to 12 integer digits and up to 3
 * fractional digits. Input is rounded to 3 fractional digits, ties to even.
 */
export class SFVDecimal {
  public readonly value: number;

  /** @throws RangeError if the value is not finite or is out of range. */
  constructor(value: number) {
    const thousandths = toThousandths(value);
    if (!(Math.abs(thousandths) <= 999_999_999_999_999)) {
      throw new RangeError(`SFV decimal out of range: ${value}`);
    }
    this.value = thousandths / 1000;
  }

  /** The canonical SFV serialization. */
  toString(): string {
    const thousandths = Math.round(this.value * 1000);
    const abs = Math.abs(thousandths);
    const frac = String(abs % 1000).padStart(3, "0").replace(/0+$/, "");
    const sign = thousandths < 0 ? "-" : "";
    return `${sign}${Math.floor(abs / 1000)}.${frac || "0"}`;
  }
}

function toThousandths(value: number): number {
  const abs = Math.abs(value);
  if (!(abs <= 1e12)) return NaN;
  // A double is exactly halfway between two thousandths only when it is an odd
  // multiple of 1/16; toFixed rounds those up, so pick the even neighbour.
  const floor = Math.floor(abs * 1000);
  const rounded =
    (abs * 16) % 2 === 1
      ? floor + (floor % 2)
      : Number(abs.toFixed(3).replace(".", ""));
  // Avoid -0.
  return value < 0 && rounded !== 0 ? -rounded : rounded;
}

export interface SFVItem {
  value: SFVBareItem;
  params?: SFVParams;
}

export interface SFVInnerList {
  items: SFVItem[];
  params?: SFVParams;
}

export interface SFVDictMember {
  key: string;
  item?: SFVItem;
  innerList?: SFVInnerList;
}

/** Component identifier for signature base construction. */
export interface ComponentIdentifier {
  name: string;
  params?: SFVParams;
}

/** Parameters that control signature generation. */
export interface SignatureParameters {
  components: ComponentIdentifier[];
  algorithm?: Algorithm;
  keyId: string;
  created?: number;
  expires?: number;
  nonce?: string;
  tag?: string;
}

/** Minimal view of an HTTP message for signature operations. */
export interface HttpMessage {
  isRequest: boolean;
  method?: string;
  url?: URL;
  statusCode?: number;
  headerValues(name: string): string[];
}

/** A key that can produce signatures. */
export interface SigningKey {
  keyId: string;
  algorithm: Algorithm;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/** A key that can verify signatures. */
export interface VerifyingKey {
  keyId: string;
  algorithm: Algorithm;
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

/** A paired signing and verifying key with the same identity and algorithm. */
export interface KeyPair {
  readonly keyId: string;
  readonly algorithm: Algorithm;
  readonly signingKey: SigningKey;
  readonly verifyingKey: VerifyingKey;
}

/** Resolves a key ID to a VerifyingKey. */
export type KeyProvider = (
  keyId: string,
  algorithm: Algorithm | undefined,
) => Promise<VerifyingKey>;

/** Result of a signing operation. */
export interface SignResult {
  label: string;
  signatureInput: string;
  signature: Uint8Array;
}

/** Result of a verification operation. */
export interface VerifyResult {
  label: string;
  keyId: string;
  algorithm?: Algorithm;
  components: ComponentIdentifier[];
  created?: number;
  expires?: number;
  nonce?: string;
}

/** Requirements for what a valid signature must contain. Used for both verification filtering and Accept-Signature negotiation. */
export interface SignatureRequirements {
  components: ComponentIdentifier[];
  keyId?: string;
  algorithm?: Algorithm;
  tag?: string;
  requireCreated?: boolean;
  requireExpires?: boolean;
}

/** Options for signature verification. */
export interface VerifyOptions {
  requiredComponents?: ComponentIdentifier[];
  /** Full signature requirements for filtering. Takes precedence over requiredComponents when set. */
  requirements?: SignatureRequirements;
  maxAgeMs?: number;
  /** Maximum allowed forward clock skew in milliseconds. Rejects signatures with created > now + maxClockSkewMs. */
  maxClockSkewMs?: number;
  rejectExpired?: boolean;
  requiredLabel?: string;
  now?: () => number;
  /** Optional callback to validate the nonce. Called after signature verification succeeds. If it throws, verification fails. */
  nonceChecker?: (nonce: string, keyId: string, algorithm?: Algorithm) => Promise<void> | void;
}
