import Foundation
import Testing
@testable import HTTPSig

private struct StaticKeyProvider: KeyProvider {
    let key: any VerifyingKey
    func resolve(keyId: String, algorithm: Algorithm?) throws -> (any VerifyingKey)? { key }
}

@Suite("SFV Decimals")
struct DecimalTests {
    static let url = URL(string: "https://example.com/")!

    @Test("Round-trips through ;key", arguments: [
        ("1.0", "1.0"),
        ("1.50", "1.5"),
        ("1.500", "1.5"),
        ("0.001", "0.001"),
        ("10.010", "10.01"),
        ("100.0", "100.0"),
        ("-1.5", "-1.5"),
        ("-0.5", "-0.5"),
        ("-0.0", "0.0"),
        ("00.5", "0.5"),
        ("999999999999.999", "999999999999.999"),
        ("-999999999999.999", "-999999999999.999"),
        ("1.5;q=0.50", "1.5;q=0.5"),
        ("(1.50 2.0);q=0.250", "(1.5 2.0);q=0.25"),
        ("1", "1"),
    ])
    func roundTrip(input: String, want: String) throws {
        let msg = RawMessage.request(method: "GET", url: Self.url, headers: [("Dict", "a=\(input)")])
        #expect(try Components.extract(ComponentIdentifier.withKey("dict", key: "a"), from: msg) == want)
    }

    @Test("Rejects malformed decimals", arguments: [
        "1.", "1.2345", "1.0000", "1234567890123.0", "0000000000001.0", "-.5", ".5", "-", "1.-5", "1.;q=1",
    ])
    func malformed(input: String) {
        #expect(throws: HttpSigError.self) { try SFV.parseDictionary("a=\(input)") }
    }

    @Test("Integers and decimals are distinct")
    func distinct() throws {
        let members = try SFV.parseDictionary("a=1, b=1.0")
        #expect(members[0].item?.value == .int(1))
        #expect(members[1].item?.value == .decimal(SFVDecimal(thousandths: 1000)!))
    }

    @Test("Rounds half to even", arguments: [
        ("1", "1.0"),
        ("0.0625", "0.062"),
        ("0.1875", "0.188"),
        ("-0.0625", "-0.062"),
        ("0.0004", "0.0"),
        ("-0.0004", "0.0"),
        ("1e-7", "0.0"),
        ("1e2", "100.0"),
        ("999999999999.999", "999999999999.999"),
        ("-999999999999.999", "-999999999999.999"),
    ])
    func rounds(input: String, want: String) {
        #expect(SFVDecimal(Decimal(string: input)!)?.description == want)
    }

    @Test("Rejects out-of-range values", arguments: ["1e12", "-1e12", "1e100", "999999999999.9999"])
    func outOfRange(input: String) {
        #expect(SFVDecimal(Decimal(string: input)!) == nil)
        #expect(SFVDecimal(Decimal.nan) == nil)
    }

    @Test("decimalValue is exact")
    func decimalValue() {
        #expect(SFVDecimal(thousandths: -1_500)?.decimalValue == Decimal(string: "-1.5"))
    }

    // A non-integer timestamp must not be treated as absent: it would be dropped
    // from the rebuilt base and so escape the signature.
    @Test("Non-integer timestamps rejected", arguments: [
        ("", true), (";created=1.5", false), (";expires=1.0", false), (";created=\"1\"", false),
    ])
    func timestamps(suffix: String, ok: Bool) throws {
        let key = HMACSHA256Key(keyId: "k", secret: Data("decimal-timestamp-test-secret".utf8))
        let params = SignatureParameters(components: [ComponentIdentifier("@method")], keyId: "k")
        let unsigned = RawMessage.request(method: "GET", url: Self.url)
        let result = try Signer.sign(msg: unsigned, label: "sig1", params: params, key: key)
        let msg = RawMessage.request(method: "GET", url: Self.url, headers: [
            ("Signature-Input", Signer.signatureInputHeader(result) + suffix),
            ("Signature", Signer.signatureHeader(result)),
        ])
        let verified = (try? Verifier.verify(
            msg: msg, provider: StaticKeyProvider(key: key), options: VerifyOptions()
        )) != nil
        #expect(verified == ok)
    }
}
