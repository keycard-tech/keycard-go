package hexutils

import (
	"encoding/hex"
	"fmt"
	"regexp"
)

var spaceReplacer = regexp.MustCompile(" ")

// HexToBytes converts a hex string to a byte slice.
// The hex string can have spaces between bytes (e.g. "01 02 03").
// Returns an error if the hex string is invalid.
func HexToBytes(s string) ([]byte, error) {
	s = spaceReplacer.ReplaceAllString(s, "")
	return hex.DecodeString(s)
}

// MustHexToBytes converts a hex string to a byte slice, panicking on error.
// Useful in tests and initialization code where invalid hex is a bug.
func MustHexToBytes(s string) []byte {
	b, err := HexToBytes(s)
	if err != nil {
		panic(fmt.Sprintf("hexutils.MustHexToBytes: %v", err))
	}
	return b
}

// BytesToHex returns an uppercase hex string of b.
func BytesToHex(b []byte) string {
	return fmt.Sprintf("%X", b)
}

// BytesToHexWithSpaces returns an uppercase hex string of b with spaces between bytes.
func BytesToHexWithSpaces(b []byte) string {
	return fmt.Sprintf("% X", b)
}
