package types

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/status-im/keycard-go/tlv"
)

// Certificate represents a card identity certificate.
type Certificate struct {
	identPub  [33]byte
	signature *Signature
}

var (
	TagCertificate = uint8(0x8A)
)

// ParseCertificate parses a certificate from card data (at least 98 bytes).
//
// Format: compressed_pubkey(33) || r(32) || s(32) || v(1)
func ParseCertificate(data []byte) (*Certificate, error) {
	if len(data) < 98 {
		return nil, fmt.Errorf("certificate data too short: expected at least 98 bytes, got %d", len(data))
	}

	identPub := data[0:33]
	r := data[33:65]
	s := data[65:97]
	recID := int32(data[97])

	// Hash the compressed public key
	msg := sha256.Sum256(identPub)

	// Recover CA public key from signature (compressed)
	caPub, err := RecoverPublicKey(recID, msg[:], r, s, true)
	if err != nil {
		return nil, fmt.Errorf("failed to recover CA public key: %w", err)
	}

	sig := &Signature{
		pubKey: caPub,
		r:      r,
		s:      s,
		v:      byte(recID),
	}

	var identPubArr [33]byte
	copy(identPubArr[:], identPub)

	return &Certificate{
		identPub:  identPubArr,
		signature: sig,
	}, nil
}

// IdentPub returns the card's identity public key as a 33-byte compressed key.
func (c *Certificate) IdentPub() [33]byte {
	return c.identPub
}

// CAPublicKey returns the recovered CA public key (compressed, 33 bytes).
func (c *Certificate) CAPublicKey() []byte {
	return c.signature.pubKey
}

// VerifyIdentity verifies a signed identity proof.
//
// Parses the TLV to extract the certificate and the signature over hash.
// Verifies the signature using the card's identity public key.
// Returns the CA public key on success.
func VerifyIdentity(hash []byte, tlvData []byte) ([]byte, error) {
	reader := tlv.NewBerTlvReader(tlvData)
	_, err := reader.EnterConstructed(tlv.TLV_SIGNATURE_TEMPLATE)
	if err != nil {
		return nil, fmt.Errorf("failed to enter signature template: %w", err)
	}

	certData, err := reader.ReadPrimitive(tlv.TLV_CERT)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	cert, err := ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// The remaining data is the signature over hash
	sigBytes := reader.PeekUnread()
	if len(sigBytes) < 2 {
		return nil, errors.New("signature data too short")
	}

	// Parse the signature - it could be raw (65 bytes: r || s || v) or DER-encoded
	var sig *ecdsa.Signature
	if len(sigBytes) == 65 {
		// Raw signature format
		rBytes := sigBytes[0:32]
		sBytes := sigBytes[32:64]

		var rScalar, sScalar secp256k1.ModNScalar
		rScalar.SetBytes((*[32]byte)(rBytes))
		sScalar.SetBytes((*[32]byte)(sBytes))
		sig = ecdsa.NewSignature(&rScalar, &sScalar)
	} else {
		// DER-encoded signature
		sig, err = ecdsa.ParseDERSignature(sigBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER signature: %w", err)
		}
	}

	// Verify using the card's identity public key
	identPubKey, err := secp256k1.ParsePubKey(cert.identPub[:])
	if err != nil {
		return nil, fmt.Errorf("invalid identity public key: %w", err)
	}

	if !sig.Verify(hash, identPubKey) {
		return nil, errors.New("identity signature verification failed")
	}

	return compressPublicKey(cert.signature.pubKey), nil
}
