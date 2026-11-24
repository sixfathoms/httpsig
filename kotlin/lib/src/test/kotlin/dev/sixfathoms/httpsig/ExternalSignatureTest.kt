package dev.sixfathoms.httpsig

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.time.Instant

/** The signatures below were computed with OpenSSL, not this library. */
class ExternalSignatureTest {

    private val input =
        """("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";x-ver=1.5;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000"""
    private val sig = "Ad8NkVPRZQqviyFbO8ThZYBK+4Wy5kmmPZvXP8n0wcE="

    private fun verify(input: String, sig: String): Verifier.VerifyResult {
        val key = Keys.hmacSHA256Key("ext", "external-signer-shared-secret".toByteArray())
        val msg = RawMessage.request(
            "GET",
            URI.create("https://example.com/path"),
            mapOf("signature-input" to listOf("sig1=$input"), "signature" to listOf("sig1=:$sig:")),
        )
        return Verifier.verify(
            msg,
            { _, _ -> key },
            Verifier.VerifyOptions(now = { Instant.ofEpochSecond(1700000010) }),
        )
    }

    @Test
    fun `sender parameter order verifies`() {
        val result = verify(input, sig)
        assertEquals("n-1", result.nonce)
        assertEquals(1700000000L, result.created)
    }

    @Test
    fun `tampered parameters rejected`() {
        val inputs = listOf(
            """("@method" "@authority" "@path");keyid="ext";tag="web-bot-auth";x-ver=1.5;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000""",
            """("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000""",
            """("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";x-ver=1.5;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000;extra=1""",
            """("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";x-ver=1.6;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000""",
        )
        for (tampered in inputs) assertThrows<HttpSigException>(tampered) { verify(tampered, sig) }
    }

    // Correctly signed, but a known parameter has the wrong type or value. Treating
    // it as absent would skip the checks that depend on it.
    @Test
    fun `malformed parameter rejected`() {
        val cases = listOf(
            """tag="t";nonce=1""" to "VwvsdElH8JP3khcMIdq+JmXG221Un6uoWf50N+oqizY=",
            """keyid="ext";alg=hmac-sha256""" to "aGPTGJuoa0VJSPmI75SNMl02fgIVE22uPJp7VB20r58=",
            """keyid="ext";alg="nope"""" to "RFa0y6Ug/IP0hT5pxR2OtrOirbw2Up5r3M/aJ8Lq3a4=",
            """keyid="ext";tag=1""" to "x3BJu6w8ENdN6a4FUxS0xlUb0uwiS3dsCmQQ+nplYnk=",
            """keyid=ext""" to "HKzZMwFV7hsG2l1Kl2mjDhKYL9HrKbPckSY/lIxLN+g=",
        )
        for ((params, sig) in cases) {
            assertThrows<HttpSigException>(params) { verify("""("@method");$params""", sig) }
        }
    }
}
