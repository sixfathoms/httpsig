package dev.sixfathoms.httpsig;

/**
 * A key that can produce signatures.
 */
public interface SigningKey {

    String keyId();

    Algorithm algorithm();

    byte[] sign(byte[] data) throws HttpSigException;
}
