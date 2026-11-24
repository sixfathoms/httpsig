package dev.sixfathoms.httpsig;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** The signatures below were computed with OpenSSL, not this library. */
class ExternalSignatureTest {

    private static final String INPUT = "(\"@method\" \"@authority\" \"@path\");tag=\"web-bot-auth\";keyid=\"ext\";x-ver=1.5;alg=\"hmac-sha256\";flag;nonce=\"n-1\";expires=4102444800;created=1700000000";
    private static final String SIG = "Ad8NkVPRZQqviyFbO8ThZYBK+4Wy5kmmPZvXP8n0wcE=";

    private static Verifier.VerifyResult verify(String input, String sig) throws HttpSigException {
        var key = Keys.hmacSHA256Key("ext", "external-signer-shared-secret".getBytes());
        var msg = RawMessage.request("GET", URI.create("https://example.com/path"), Map.of(
            "signature-input", List.of("sig1=" + input),
            "signature", List.of("sig1=:" + sig + ":")));
        var options = Verifier.VerifyOptions.builder().now(() -> Instant.ofEpochSecond(1700000010)).build();
        return Verifier.verify(msg, (id, alg) -> key, options, null);
    }

    @Test
    void senderParameterOrder_verifies() throws Exception {
        var result = verify(INPUT, SIG);
        assertEquals("n-1", result.nonce());
        assertEquals(1700000000L, result.created());
    }

    @Test
    void tamperedParameters_rejected() {
        for (var input : List.of(
                "(\"@method\" \"@authority\" \"@path\");keyid=\"ext\";tag=\"web-bot-auth\";x-ver=1.5;alg=\"hmac-sha256\";flag;nonce=\"n-1\";expires=4102444800;created=1700000000",
                "(\"@method\" \"@authority\" \"@path\");tag=\"web-bot-auth\";keyid=\"ext\";alg=\"hmac-sha256\";flag;nonce=\"n-1\";expires=4102444800;created=1700000000",
                "(\"@method\" \"@authority\" \"@path\");tag=\"web-bot-auth\";keyid=\"ext\";x-ver=1.5;alg=\"hmac-sha256\";flag;nonce=\"n-1\";expires=4102444800;created=1700000000;extra=1",
                "(\"@method\" \"@authority\" \"@path\");tag=\"web-bot-auth\";keyid=\"ext\";x-ver=1.6;alg=\"hmac-sha256\";flag;nonce=\"n-1\";expires=4102444800;created=1700000000")) {
            assertThrows(HttpSigException.class, () -> verify(input, SIG), input);
        }
    }

    // Correctly signed, but a known parameter has the wrong type or value. Treating
    // it as absent would skip the checks that depend on it.
    @Test
    void malformedParameter_rejected() {
        String[][] cases = {
            {"tag=\"t\";nonce=1", "VwvsdElH8JP3khcMIdq+JmXG221Un6uoWf50N+oqizY="},
            {"keyid=\"ext\";alg=hmac-sha256", "aGPTGJuoa0VJSPmI75SNMl02fgIVE22uPJp7VB20r58="},
            {"keyid=\"ext\";alg=\"nope\"", "RFa0y6Ug/IP0hT5pxR2OtrOirbw2Up5r3M/aJ8Lq3a4="},
            {"keyid=\"ext\";tag=1", "x3BJu6w8ENdN6a4FUxS0xlUb0uwiS3dsCmQQ+nplYnk="},
            {"keyid=ext", "HKzZMwFV7hsG2l1Kl2mjDhKYL9HrKbPckSY/lIxLN+g="},
        };
        for (var c : cases) {
            assertThrows(HttpSigException.class, () -> verify("(\"@method\");" + c[0], c[1]), c[0]);
        }
    }

    @Test
    void componentParameterOrder_preserved() {
        for (var order : List.of(
                List.of("a", "b", "c", "d", "e"), List.of("e", "d", "c", "b", "a"), List.of("c", "a", "e", "b", "d"))) {
            var params = new LinkedHashMap<String, Object>();
            order.forEach(k -> params.put(k, true));
            assertEquals("\"x\";" + String.join(";", order),
                SFV.serializeComponentId(ComponentIdentifier.withParams("x", params)));
        }
    }
}
