package types

import (
	"bytes"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/keycard-tech/keycard-go/v4/apdu"
)

var (
	TagSignatureTemplate = uint8(0xA0)
	TagRawSignature      = uint8(0x80)
	TagSchnorrSignature  = uint8(0x88)
)

type Signature struct {
	pubKey []byte
	r      []byte
	s      []byte
	v      byte
}

func ParseSignature(message, resp []byte) (*Signature, error) {
	// check for old template first because TagRawSignature matches the pubkey tag
	template, err := apdu.FindTag(resp, apdu.Tag{TagSignatureTemplate})
	if err == nil {
		return parseLegacySignature(message, template)
	}

	sig, err := apdu.FindTag(resp, apdu.Tag{TagRawSignature})

	if err != nil {
		return nil, err
	}

	return ParseRecoverableSignature(message, sig)
}

func ParseRecoverableSignature(message, sig []byte) (*Signature, error) {
	if len(sig) != 65 {
		return nil, errors.New("invalid signature")
	}

	pubKey, err := crypto.Ecrecover(message, sig)
	if err != nil {
		return nil, err
	}

	return &Signature{
		pubKey: pubKey,
		r:      sig[0:32],
		s:      sig[32:64],
		v:      sig[64],
	}, nil
}

func DERSignatureToRS(tlv []byte) ([]byte, []byte, error) {
	r, err := apdu.FindTagN(tlv, 0, apdu.Tag{0x30}, apdu.Tag{0x02})
	if err == nil {
		// DER-encoded signature (tag 0x30 containing INTEGERs)
		if len(r) > 32 {
			r = r[len(r)-32:]
		}

		s, err := apdu.FindTagN(tlv, 1, apdu.Tag{0x30}, apdu.Tag{0x02})
		if err != nil {
			return nil, nil, err
		}

		if len(s) > 32 {
			s = s[len(s)-32:]
		}

		return r, s, nil
	}

	// Fall back to Schnorr signature: tag 0x88 contains raw 64 bytes (r||s)
	schnorr, err := apdu.FindTag(tlv, apdu.Tag{TagSchnorrSignature})
	if err != nil {
		return nil, nil, err
	}

	if len(schnorr) != 64 {
		return nil, nil, errors.New("schnorr signature must be 64 bytes")
	}

	return schnorr[0:32], schnorr[32:64], nil
}

func (s *Signature) PubKey() []byte {
	return s.pubKey
}

func (s *Signature) R() []byte {
	return s.r
}

func (s *Signature) S() []byte {
	return s.s
}

func (s *Signature) V() byte {
	return s.v
}

func parseLegacySignature(message, template []byte) (*Signature, error) {
	pubKey, err := apdu.FindTag(template, apdu.Tag{0x80})
	if err != nil {
		return nil, err
	}

	r, s, err := DERSignatureToRS(template)
	if err != nil {
		return nil, err
	}

	// Schnorr signatures (tag 0x88) don't support pubkey recovery via ECDSA.
	// The card already provides the pubkey in tag 0x80, so we skip calculateV.
	_, isSchnorrErr := apdu.FindTag(template, apdu.Tag{TagSchnorrSignature})
	isSchnorr := isSchnorrErr == nil

	var v byte
	if !isSchnorr {
		v, err = calculateV(message, pubKey, r, s)
		if err != nil {
			return nil, err
		}
	}

	return &Signature{
		pubKey: pubKey,
		r:      r,
		s:      s,
		v:      v,
	}, nil
}

func calculateV(message, pubKey, r, s []byte) (v byte, err error) {
	rs := append(r, s...)
	for i := 0; i < 4; i++ {
		v = byte(i)
		sig := append(rs, v)
		rec, err := crypto.Ecrecover(message, sig)
		if err != nil {
			return v, err
		}

		if len(pubKey) == 33 {
			rec = compressPublicKey(rec)
		}

		if bytes.Equal(pubKey, rec) {
			return v, nil
		}
	}

	return v, err
}

func compressPublicKey(pubKey []byte) []byte {
	if len(pubKey) == 33 {
		return pubKey
	}

	if (pubKey[64] & 1) == 1 {
		pubKey[0] = 3
	} else {
		pubKey[0] = 2
	}

	return pubKey[0:33]
}

// RecoverPublicKey performs standard secp256k1 pubkey recovery from ECDSA signature components.
//
// recID must be 0..=3. hash must be 32 bytes. r and s must be 32 bytes each.
// If compressed is true, returns a 33-byte compressed public key; otherwise 65-byte uncompressed.
func RecoverPublicKey(recID int32, hash, r, s []byte, compressed bool) ([]byte, error) {
	if recID < 0 || recID > 3 {
		return nil, errors.New("recID must be 0..=3")
	}
	if len(hash) != 32 || len(r) != 32 || len(s) != 32 {
		return nil, errors.New("hash, r, and s must each be 32 bytes")
	}

	// Build compact signature in decred format:
	// byte[0]: recovery code (27 + recID, or 31 + recID if compressed)
	// bytes[1:33]: r
	// bytes[33:65]: s
	compactSig := make([]byte, 65)
	recoveryCode := byte(27 + recID)
	if compressed {
		recoveryCode += 4
	}
	compactSig[0] = recoveryCode
	copy(compactSig[1:33], r)
	copy(compactSig[33:65], s)

	pubKey, _, err := ecdsa.RecoverCompact(compactSig, hash)
	if err != nil {
		return nil, err
	}

	if compressed {
		return pubKey.SerializeCompressed(), nil
	}
	return pubKey.SerializeUncompressed(), nil
}

// EthereumAddress returns the Ethereum address of the signing key.
func (s *Signature) EthereumAddress() [20]byte {
	return ToEthereumAddress(s.pubKey)
}
