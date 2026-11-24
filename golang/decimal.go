package httpsig

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// maxDecimalThousandths is the largest Decimal magnitude, 999999999999.999.
const maxDecimalThousandths = 999_999_999_999_999

// Decimal is an SFV Decimal (RFC 8941 Section 3.3.2): up to 12 integer digits
// and up to 3 fractional digits. It is exact, comparable with ==, and distinct
// from an Integer: Decimal 1.0 and int64 1 serialize differently.
type Decimal struct {
	thousandths int64
}

// NewDecimal converts f to a Decimal, rounding to three fractional digits with
// ties to even. It returns an error if f is not finite or is out of range.
func NewDecimal(f float64) (Decimal, error) {
	if math.IsNaN(f) || math.Abs(f) > 1e12 {
		return Decimal{}, fmt.Errorf("sfv: decimal out of range: %v", f)
	}
	// FormatFloat rounds the exact value of f, unlike math.RoundToEven(f*1000).
	digits := strings.Replace(strconv.FormatFloat(f, 'f', 3, 64), ".", "", 1)
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n > maxDecimalThousandths || n < -maxDecimalThousandths {
		return Decimal{}, fmt.Errorf("sfv: decimal out of range: %v", f)
	}
	return Decimal{thousandths: n}, nil
}

// Float64 returns the nearest float64 to d.
func (d Decimal) Float64() float64 {
	return float64(d.thousandths) / 1000
}

// String returns the canonical SFV serialization of d.
func (d Decimal) String() string {
	n, sign := d.thousandths, ""
	if n < 0 {
		n, sign = -n, "-"
	}
	frac := strings.TrimRight(fmt.Sprintf("%03d", n%1000), "0")
	if frac == "" {
		frac = "0"
	}
	return sign + strconv.FormatInt(n/1000, 10) + "." + frac
}
