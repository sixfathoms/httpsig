package httpsig

import (
	"math"
	"net/http"
	"testing"
)

func TestDecimalRoundTrip(t *testing.T) {
	tests := []struct{ in, want string }{
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
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			msg := &RawMessage{IsReq: true, Headers: http.Header{"Dict": {"a=" + tt.in}}}
			got, err := extractComponent(ComponentWithKey("dict", "a"), msg, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDecimalRejected(t *testing.T) {
	for _, in := range []string{"1.", "1.2345", "1.0000", "1234567890123.0", "0000000000001.0", "-.5", ".5", "-", "1.-5", "1.;q=1"} {
		if _, err := ParseDictionary("a=" + in); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

func TestDecimalTypes(t *testing.T) {
	members, err := ParseDictionary("a=1, b=1.0")
	if err != nil {
		t.Fatal(err)
	}
	if v := members[0].Item.Value; v != int64(1) {
		t.Errorf("a = %T %v, want int64", v, v)
	}
	one, _ := NewDecimal(1)
	if v := members[1].Item.Value; v != one {
		t.Errorf("b = %T %v, want Decimal", v, v)
	}
}

func TestNewDecimal(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{1, "1.0"},
		{0.0625, "0.062"}, // exact tie, to even
		{0.1875, "0.188"}, // exact tie, to even
		{-0.0625, "-0.062"},
		{0.0004, "0.0"},
		{-0.0004, "0.0"},
		{1e-7, "0.0"},
		{999999999999.999, "999999999999.999"},
	}
	for _, tt := range tests {
		d, err := NewDecimal(tt.in)
		if err != nil || d.String() != tt.want {
			t.Errorf("NewDecimal(%v) = %v, %v; want %s", tt.in, d, err, tt.want)
		}
	}
	if d, _ := NewDecimal(-1.5); d.Float64() != -1.5 {
		t.Errorf("Float64 = %v", d.Float64())
	}
	for _, f := range []float64{1e12, -1e12, 1e300, 999999999999.9999, math.NaN(), math.Inf(1)} {
		if d, err := NewDecimal(f); err == nil {
			t.Errorf("NewDecimal(%v) = %v, want error", f, d)
		}
	}
}

// A non-integer timestamp must not be treated as absent: it would be dropped
// from the rebuilt base and so escape the signature.
func TestNonIntegerTimestampRejected(t *testing.T) {
	key := NewHMACSHA256Key("k", []byte("decimal-timestamp-test-secret"))
	provider := func(string, Algorithm) (VerifyingKey, error) { return key, nil }
	newMsg := func() *RawMessage {
		return &RawMessage{IsReq: true, Meth: "GET", TargetURI: mustParseURL(t, "https://example.com/"), Headers: http.Header{}}
	}
	res, err := SignMessage(newMsg(), "sig1", SignatureParameters{Components: []ComponentIdentifier{Component("@method")}, KeyID: "k"}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	for suffix, ok := range map[string]bool{"": true, ";created=1.5": false, ";expires=1.0": false, `;created="1"`: false} {
		msg := newMsg()
		msg.Headers.Set("Signature-Input", SignatureInputHeader(res)+suffix)
		msg.Headers.Set("Signature", SignatureHeader(res))
		if _, err := VerifyMessage(msg, provider, nil, nil); (err == nil) != ok {
			t.Errorf("suffix %q: err = %v, want ok = %v", suffix, err, ok)
		}
	}
}
