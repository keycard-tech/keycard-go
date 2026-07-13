package types

import "github.com/status-im/keycard-go/apdu"

// Channel is an interface with a Send method to send apdu commands and receive apdu responses.
type Channel interface {
	Send(*apdu.Command) (*apdu.Response, error)
}

// PairingInfo holds Secure Channel V1 pairing data.
//
// Deprecated: use types.Pairing instead, which provides a safer API with
// typed fields (Key() returns [32]byte, Index() returns uint8) and
// Zeroize() for memory clearing.
type PairingInfo struct {
	Key   []byte
	Index int
}