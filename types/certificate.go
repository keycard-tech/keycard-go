package types

import (
	"crypto/sha256"
	"errors"

	"github.com/status-im/keycard-go/apdu"
)

type Certificate struct {
	identPub  []byte
	signature *Signature
}

var (
	TagCertificate = uint8(0x8A)
)

func ParseCertificate(data []byte) (*Certificate, error) {
	if len(data) != 98 {
		return nil, errors.New("certificate must be 98 byte long")
	}

	identPub := data[0:33]
	sigData := data[33:98]
	msg := sha256.Sum256(identPub)

	sig, err := ParseRecoverableSignature(msg[:], sigData)
	if err != nil {
		return nil, err
	}

	return &Certificate{
		identPub:  identPub,
		signature: sig,
	}, nil
}

// IdentPub returns the card's identity public key as a 33-byte compressed key.
func (c *Certificate) IdentPub() [33]byte {
	var pub [33]byte
	copy(pub[:], c.identPub)
	return pub
}

// CAPublicKey returns the recovered CA public key (compressed, 33 bytes).
func (c *Certificate) CAPublicKey() []byte {
	return c.signature.PubKey()
}

func VerifyIdentity(challenge []byte, tlvData []byte) ([]byte, error) {
	template, err := apdu.FindTag(tlvData, apdu.Tag{TagSignatureTemplate})
	if err != nil {
		return nil, err
	}

	certData, err := apdu.FindTag(template, apdu.Tag{TagCertificate})
	if err != nil {
		return nil, err
	}

	cert, err := ParseCertificate(certData)
	if err != nil {
		return nil, err
	}

	r, s, err := DERSignatureToRS(template)
	if err != nil {
		return nil, err
	}

	// TODO: investigate why verify signature fails but recovery works
	_, err = calculateV(challenge, cert.identPub, r, s)

	if err != nil {
		return nil, errors.New("invalid signature")
	}

	return compressPublicKey(cert.signature.pubKey), nil
}
