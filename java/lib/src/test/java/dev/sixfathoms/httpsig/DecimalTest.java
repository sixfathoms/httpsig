package dev.sixfathoms.httpsig;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigDecimal;
import java.net.URI;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class DecimalTest {

    private static final URI URL = URI.create("https://example.com/");

    @Test
    void roundTripThroughKey() throws Exception {
        String[][] cases = {
            {"1.0", "1.0"},
            {"1.50", "1.5"},
            {"1.500", "1.5"},
            {"0.001", "0.001"},
            {"10.010", "10.01"},
            {"100.0", "100.0"},
            {"-1.5", "-1.5"},
            {"-0.5", "-0.5"},
            {"-0.0", "0.0"},
            {"00.5", "0.5"},
            {"999999999999.999", "999999999999.999"},
            {"-999999999999.999", "-999999999999.999"},
            {"1.5;q=0.50", "1.5;q=0.5"},
            {"(1.50 2.0);q=0.250", "(1.5 2.0);q=0.25"},
            {"1", "1"},
        };
        for (var c : cases) {
            var msg = RawMessage.request("GET", URL, Map.of("dict", List.of("a=" + c[0])));
            assertEquals(c[1], Components.extract(ComponentIdentifier.withKey("dict", "a"), msg, null), c[0]);
        }
    }

    @Test
    void malformedRejected() {
        for (var in : List.of("1.", "1.2345", "1.0000", "1234567890123.0", "0000000000001.0",
                "-.5", ".5", "-", "1.-5", "1.;q=1")) {
            assertThrows(HttpSigException.class, () -> SFV.parseDictionary("a=" + in), in);
        }
    }

    @Test
    void integersAndDecimalsAreDistinct() throws Exception {
        var members = SFV.parseDictionary("a=1, b=1.0");
        assertEquals(1, ((SFV.Item) members.get(0).value()).value());
        assertEquals(new SFV.Decimal(1000), ((SFV.Item) members.get(1).value()).value());
    }

    @Test
    void ofRoundsHalfEven() {
        String[][] cases = {
            {"1", "1.0"},
            {"0.0625", "0.062"},
            {"0.1875", "0.188"},
            {"-0.0625", "-0.062"},
            {"0.0004", "0.0"},
            {"-0.0004", "0.0"},
            {"1E-7", "0.0"},
            {"1E+2", "100.0"},
            {"999999999999.999", "999999999999.999"},
        };
        for (var c : cases) {
            assertEquals(c[1], SFV.serializeBareItem(SFV.Decimal.of(new BigDecimal(c[0]))), c[0]);
        }
        for (var in : List.of("1E+12", "-1E+12", "1E+300", "999999999999.9999")) {
            assertThrows(IllegalArgumentException.class, () -> SFV.Decimal.of(new BigDecimal(in)), in);
        }
    }

    // A non-integer timestamp must not be treated as absent: it would be dropped
    // from the rebuilt base and so escape the signature.
    @Test
    void nonIntegerTimestampRejected() throws Exception {
        var key = Keys.hmacSHA256Key("k", "decimal-timestamp-test-secret".getBytes());
        var params = SignatureParameters.builder().component("@method").keyId("k").build();
        var result = Signer.sign(RawMessage.request("GET", URL, Map.of()), "sig1", params, key, null);
        var options = new Verifier.VerifyOptions(null, null, null, null, null, null, null);

        Verifier.verify(signed(result, ""), (id, alg) -> key, options, null);
        for (var suffix : List.of(";created=1.5", ";expires=1.0", ";created=\"1\"")) {
            var msg = signed(result, suffix);
            assertThrows(HttpSigException.class,
                () -> Verifier.verify(msg, (id, alg) -> key, options, null), suffix);
        }
    }

    private static HttpMessage signed(Signer.SignResult result, String suffix) {
        return RawMessage.request("GET", URL, Map.of(
            "signature-input", List.of(Signer.signatureInputHeader(result) + suffix),
            "signature", List.of(Signer.signatureHeader(result))));
    }
}
