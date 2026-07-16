package types

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/keycard-tech/keycard-go/v4/tlv"
)
// Certificate represents a card identity certificate.
type Certificate struct {
	identPriv []byte
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

// IdentPriv returns the card's identity private key (32 bytes).
// Returns nil if the certificate was parsed from external data (no private key).
func (c *Certificate) IdentPriv() []byte {
	return c.identPriv
}

// RecID returns the signature recovery ID.
func (c *Certificate) RecID() byte {
	return c.signature.v
}

// ToStoreData serializes the certificate for storage.
//
// Format: identPub(33) || r(32) || s(32) || recID(1) || identPriv(32)
// Total: 130 bytes
//
// Requires the private key to be set (i.e., certificate was created, not parsed).
func (c *Certificate) ToStoreData() ([]byte, error) {
	if c.identPriv == nil {
		return nil, errors.New("private key not set, cannot serialize for storage")
	}

	data := make([]byte, 0, 130)
	data = append(data, c.identPub[:]...)
	data = append(data, c.signature.r...)
	data = append(data, c.signature.s...)
	data = append(data, c.signature.v)
	data = append(data, c.identPriv...)
	return data, nil
}

// GenerateIdentKeyPair generates a new secp256k1 keypair for identity.
func GenerateIdentKeyPair() (*secp256k1.PrivateKey, error) {
	return secp256k1.GeneratePrivateKey()
}

// CreateCertificate creates a certificate signed by the CA over the given identity public key.
//
// The CA private key signs SHA256(identPub) and the resulting signature (r, s, recID)
// is stored alongside the identity public key.
func CreateCertificate(caPriv *secp256k1.PrivateKey, identPub [33]byte, identPriv []byte) (*Certificate, error) {
	// Hash the compressed public key
	hash := sha256.Sum256(identPub[:])

	// Sign the hash with the CA private key
	sig := ecdsa.Sign(caPriv, hash[:])

	// Extract r and s from DER-encoded signature
	r, s, err := DERSignatureToRS(sig.Serialize())
	if err != nil {
		return nil, fmt.Errorf("failed to extract r/s from signature: %w", err)
	}

	// Pad r and s to 32 bytes
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(r):], r)
	copy(sPadded[32-len(s):], s)

	// Calculate recID by trying all 4 possibilities and checking which recovers the CA public key
	caPub := caPriv.PubKey()
	caPubCompressed := caPub.SerializeCompressed()
	var recID byte
	for i := byte(0); i < 4; i++ {
		recovered, err := RecoverPublicKey(int32(i), hash[:], rPadded, sPadded, true)
		if err != nil {
			continue
		}
		if bytes.Equal(recovered, caPubCompressed) {
			recID = i
			break
		}
	}

	return &Certificate{
		identPriv: identPriv,
		identPub:  identPub,
		signature: &Signature{
			pubKey: caPubCompressed,
			r:      rPadded,
			s:      sPadded,
			v:      recID,
		},
	}, nil
}

// GenerateNewCertificate generates a new identity keypair and creates a certificate signed by the CA.
func GenerateNewCertificate(caPriv *secp256k1.PrivateKey) (*Certificate, error) {
	identPriv, err := GenerateIdentKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity keypair: %w", err)
	}

	identPubBytes := identPriv.PubKey().SerializeCompressed()
	var identPub [33]byte
	copy(identPub[:], identPubBytes)

	// Serialize private key to 32 bytes
	privBytes := identPriv.Serialize()

	return CreateCertificate(caPriv, identPub, privBytes)
}
