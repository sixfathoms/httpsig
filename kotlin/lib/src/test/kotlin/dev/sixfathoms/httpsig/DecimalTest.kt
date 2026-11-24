package dev.sixfathoms.httpsig

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.math.BigDecimal
import java.net.URI

class DecimalTest {

    private val url = URI.create("https://example.com/")

    @Test
    fun `round-trips through key`() {
        val cases = listOf(
            "1.0" to "1.0",
            "1.50" to "1.5",
            "1.500" to "1.5",
            "0.001" to "0.001",
            "10.010" to "10.01",
            "100.0" to "100.0",
            "-1.5" to "-1.5",
            "-0.5" to "-0.5",
            "-0.0" to "0.0",
            "00.5" to "0.5",
            "999999999999.999" to "999999999999.999",
            "-999999999999.999" to "-999999999999.999",
            "1.5;q=0.50" to "1.5;q=0.5",
            "(1.50 2.0);q=0.250" to "(1.5 2.0);q=0.25",
            "1" to "1",
        )
        for ((input, want) in cases) {
            val msg = RawMessage.request("GET", url, mapOf("dict" to listOf("a=$input")))
            assertEquals(want, Components.extract(ComponentIdentifier.withKey("dict", "a"), msg, null))
        }
    }

    @Test
    fun `malformed decimals rejected`() {
        val inputs = listOf(
            "1.", "1.2345", "1.0000", "1234567890123.0", "0000000000001.0",
            "-.5", ".5", "-", "1.-5", "1.;q=1", "١.5", "1.٥",
        )
        for (input in inputs) {
            assertThrows<HttpSigException>(input) { SFV.parseDictionary("a=$input") }
        }
    }

    @Test
    fun `integers and decimals are distinct`() {
        val (a, b) = SFV.parseDictionary("a=1, b=1.0")
        assertEquals(1, (a.value as SFV.Item).value)
        assertEquals(SFV.Decimal(1000), (b.value as SFV.Item).value)
    }

    @Test
    fun `of rounds half even`() {
        val cases = listOf(
            "1" to "1.0",
            "0.0625" to "0.062",
            "0.1875" to "0.188",
            "-0.0625" to "-0.062",
            "0.0004" to "0.0",
            "-0.0004" to "0.0",
            "1E-7" to "0.0",
            "1E+2" to "100.0",
            "999999999999.999" to "999999999999.999",
        )
        for ((input, want) in cases) {
            assertEquals(want, SFV.serializeBareItem(SFV.Decimal.of(BigDecimal(input))))
        }
        for (input in listOf("1E+12", "-1E+12", "1E+300", "999999999999.9999")) {
            assertThrows<IllegalArgumentException>(input) { SFV.Decimal.of(BigDecimal(input)) }
        }
    }

    // A non-integer timestamp must not be treated as absent: it would be dropped
    // from the rebuilt base and so escape the signature.
    @Test
    fun `non-integer timestamp rejected`() {
        val key = Keys.hmacSHA256Key("k", "decimal-timestamp-test-secret".toByteArray())
        val params = SignatureParameters.builder().component("@method").keyId("k").build()
        val result = Signer.sign(RawMessage.request("GET", url), "sig1", params, key)
        fun verify(suffix: String) = Verifier.verify(
            RawMessage.request(
                "GET",
                url,
                mapOf(
                    "signature-input" to listOf(Signer.signatureInputHeader(result) + suffix),
                    "signature" to listOf(Signer.signatureHeader(result)),
                ),
            ),
            { _, _ -> key },
        )

        verify("")
        for (suffix in listOf(";created=1.5", ";expires=1.0", ";created=\"1\"")) {
            assertThrows<HttpSigException>(suffix) { verify(suffix) }
        }
    }
}
