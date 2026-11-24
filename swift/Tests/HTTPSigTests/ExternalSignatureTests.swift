import Foundation
import Testing
@testable import HTTPSig

private struct StaticKeyProvider: KeyProvider {
    let key: any VerifyingKey
    func resolve(keyId: String, algorithm: Algorithm?) throws -> (any VerifyingKey)? { key }
}

/// The signatures below were computed with OpenSSL, not this library.
@Suite("Signatures from other implementations")
struct ExternalSignatureTests {
    static let input = #"("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";x-ver=1.5;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000"#
    static let sig = "Ad8NkVPRZQqviyFbO8ThZYBK+4Wy5kmmPZvXP8n0wcE="

    func verify(_ input: String, _ sig: String) throws -> VerifyResult {
        let key = HMACSHA256Key(keyId: "ext", secret: Data("external-signer-shared-secret".utf8))
        let msg = RawMessage.request(method: "GET", url: URL(string: "https://example.com/path")!, headers: [
            ("Signature-Input", "sig1=\(input)"),
            ("Signature", "sig1=:\(sig):"),
        ])
        var options = VerifyOptions()
        options.now = { Date(timeIntervalSince1970: 1_700_000_010) }
        return try Verifier.verify(msg: msg, provider: StaticKeyProvider(key: key), options: options)
    }

    @Test("Verifies parameters in the sender's order")
    func senderOrder() throws {
        let result = try verify(Self.input, Self.sig)
        #expect(result.nonce == "n-1")
        #expect(result.created == 1_700_000_000)
    }

    @Test("Rejects tampered parameters", arguments: [
        #"("@method" "@authority" "@path");keyid="ext";tag="web-bot-auth";x-ver=1.5;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000"#,
        #"("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000"#,
        #"("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";x-ver=1.5;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000;extra=1"#,
        #"("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";x-ver=1.6;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000"#,
    ])
    func tampered(input: String) {
        #expect(throws: HttpSigError.self) { try verify(input, Self.sig) }
    }

    // Correctly signed, but a known parameter has the wrong type or value. Treating
    // it as absent would skip the checks that depend on it.
    @Test("Rejects malformed parameters", arguments: [
        (#"tag="t";nonce=1"#, "VwvsdElH8JP3khcMIdq+JmXG221Un6uoWf50N+oqizY="),
        (#"keyid="ext";alg=hmac-sha256"#, "aGPTGJuoa0VJSPmI75SNMl02fgIVE22uPJp7VB20r58="),
        (#"keyid="ext";alg="nope""#, "RFa0y6Ug/IP0hT5pxR2OtrOirbw2Up5r3M/aJ8Lq3a4="),
        (#"keyid="ext";tag=1"#, "x3BJu6w8ENdN6a4FUxS0xlUb0uwiS3dsCmQQ+nplYnk="),
        (#"keyid=ext"#, "HKzZMwFV7hsG2l1Kl2mjDhKYL9HrKbPckSY/lIxLN+g="),
    ])
    func malformed(params: String, sig: String) {
        #expect(throws: HttpSigError.self) { try verify(#"("@method");"# + params, sig) }
    }
}
