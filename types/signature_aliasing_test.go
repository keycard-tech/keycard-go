package types

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestCalculateVPreservesSignatureComponents(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	hash := crypto.Keccak256([]byte("keycard legacy signature regression"))
	signed, err := crypto.Sign(hash, key)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate r and s sharing one DER response buffer.
	backing := make([]byte, 65)
	copy(backing[:32], signed[:32])
	copy(backing[33:], signed[32:64])

	r := backing[:32]
	s := backing[33:65]
	expectedS := bytes.Clone(s)

	v, err := calculateV(
		hash,
		crypto.FromECDSAPub(&key.PublicKey),
		r,
		s,
	)
	if err != nil {
		t.Fatal(err)
	}

	if v != signed[64] {
		t.Errorf("recovery ID: got %d, want %d", v, signed[64])
	}

	if !bytes.Equal(s, expectedS) {
		t.Error("calculateV corrupted the original S component")
	}
}
