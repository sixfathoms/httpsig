package httpsig

import (
	"net/http"
	"testing"
	"time"
)

const externalSecret = "external-signer-shared-secret"

// The signatures below were computed with OpenSSL, not this library.
func verifyExternal(t *testing.T, input, sig string) (*VerifyResult, error) {
	t.Helper()
	key := NewHMACSHA256Key("ext", []byte(externalSecret))
	msg := &RawMessage{IsReq: true, Meth: "GET", TargetURI: mustParseURL(t, "https://example.com/path"), Headers: http.Header{}}
	msg.Headers.Set("Signature-Input", "sig1="+input)
	msg.Headers.Set("Signature", "sig1=:"+sig+":")
	return VerifyMessage(msg, func(string, Algorithm) (VerifyingKey, error) { return key, nil },
		&VerifyOptions{Now: func() time.Time { return time.Unix(1700000010, 0) }}, nil)
}

const (
	externalInput = `("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";x-ver=1.5;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000`
	externalSig   = "Ad8NkVPRZQqviyFbO8ThZYBK+4Wy5kmmPZvXP8n0wcE="
)

func TestVerifyExternalParameterOrder(t *testing.T) {
	res, err := verifyExternal(t, externalInput, externalSig)
	if err != nil {
		t.Fatal(err)
	}
	if *res.Nonce != "n-1" || *res.Created != 1700000000 || *res.Expires != 4102444800 {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestVerifyExternalTampered(t *testing.T) {
	for name, input := range map[string]string{
		"reordered": `("@method" "@authority" "@path");keyid="ext";tag="web-bot-auth";x-ver=1.5;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000`,
		"removed":   `("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000`,
		"added":     externalInput + ";extra=1",
		"changed":   `("@method" "@authority" "@path");tag="web-bot-auth";keyid="ext";x-ver=1.6;alg="hmac-sha256";flag;nonce="n-1";expires=4102444800;created=1700000000`,
	} {
		if _, err := verifyExternal(t, input, externalSig); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// Correctly signed, but a known parameter has the wrong type or value. Treating
// it as absent would skip the checks that depend on it.
func TestVerifyMalformedParameter(t *testing.T) {
	for params, sig := range map[string]string{
		`tag="t";nonce=1`:             "VwvsdElH8JP3khcMIdq+JmXG221Un6uoWf50N+oqizY=",
		`keyid="ext";alg=hmac-sha256`: "aGPTGJuoa0VJSPmI75SNMl02fgIVE22uPJp7VB20r58=",
		`keyid="ext";alg="nope"`:      "RFa0y6Ug/IP0hT5pxR2OtrOirbw2Up5r3M/aJ8Lq3a4=",
		`keyid="ext";tag=1`:           "x3BJu6w8ENdN6a4FUxS0xlUb0uwiS3dsCmQQ+nplYnk=",
		`keyid=ext`:                   "HKzZMwFV7hsG2l1Kl2mjDhKYL9HrKbPckSY/lIxLN+g=",
	} {
		if _, err := verifyExternal(t, `("@method");`+params, sig); err == nil {
			t.Errorf("%s: expected error", params)
		}
	}
}
