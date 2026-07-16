package types

import (
	"encoding/base64"
	"fmt"

	"github.com/keycard-tech/keycard-go/v4/crypto"
)

// Pairing holds Secure Channel V1 pairing data.
type Pairing struct {
	key   [32]byte
	index uint8
}

// NewPairing creates a new Pairing from a derived key and slot index.
func NewPairing(key [32]byte, index uint8) *Pairing {
	return &Pairing{
		key:   key,
		index: index,
	}
}

// PairingFromBytes deserializes pairing data from bytes.
// Format: byte 0 is index, bytes 1..=32 are the key.
func PairingFromBytes(data []byte) (*Pairing, error) {
	if len(data) < 33 {
		return nil, fmt.Errorf("pairing data too short: expected 33 bytes, got %d", len(data))
	}
	var key [32]byte
	copy(key[:], data[1:33])
	return &Pairing{
		key:   key,
		index: data[0],
	}, nil
}

// PairingFromBase64 base64-decodes then calls PairingFromBytes.
func PairingFromBase64(b64 string) (*Pairing, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode pairing data: %w", err)
	}
	return PairingFromBytes(data)
}

// ToBytes serializes to bytes: index byte followed by key bytes.
func (p *Pairing) ToBytes() []byte {
	buf := make([]byte, 33)
	buf[0] = p.index
	copy(buf[1:], p.key[:])
	return buf
}

// ToBase64 serializes then base64-encodes.
func (p *Pairing) ToBase64() string {
	return base64.StdEncoding.EncodeToString(p.ToBytes())
}

// Key returns the pairing key.
func (p *Pairing) Key() [32]byte {
	return p.key
}

// Index returns the pairing slot index.
func (p *Pairing) Index() uint8 {
	return p.index
}

// Zeroize clears the pairing key from memory.
func (p *Pairing) Zeroize() {
	crypto.Zeroize(p.key[:])
}
