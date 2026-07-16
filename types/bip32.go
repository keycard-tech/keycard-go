package types

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/keycard-tech/keycard-go/v4/crypto"
	"github.com/keycard-tech/keycard-go/v4/tlv"
)

// Bip32KeyPair represents a BIP32 keypair with optional private key, chain code, and public key.
type Bip32KeyPair struct {
	privateKey []byte
	chainCode  []byte
	publicKey  []byte
}

// Bip32KeyPairFromBinarySeed derives a master key from a BIP32 binary seed.
// Uses HMAC-SHA512(key="Bitcoin seed", msg=seed).
// Left 32 bytes = private key, right 32 bytes = chain code.
func Bip32KeyPairFromBinarySeed(seed []byte) *Bip32KeyPair {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	hash := mac.Sum(nil)

	privateKey := make([]byte, 32)
	copy(privateKey, hash[:32])
	chainCode := make([]byte, 32)
	copy(chainCode, hash[32:])

	// Zeroize the combined hash now that parts are copied
	crypto.Zeroize(hash)

	return newBip32KeyPair(privateKey, chainCode, nil)
}

// Bip32KeyPairFromTLV parses a BIP32 keypair from TLV data (e.g., EXPORT KEY response).
func Bip32KeyPairFromTLV(tlvData []byte) (*Bip32KeyPair, error) {
	reader := tlv.NewBerTlvReader(tlvData)
	_, err := reader.EnterConstructed(tlv.TLV_KEY_TEMPLATE)
	if err != nil {
		return nil, fmt.Errorf("failed to enter key template: %w", err)
	}

	var pubKey, privKey, chainCode []byte

	// Tags appear in order: PUB_KEY (optional), PRIV_KEY, CHAIN_CODE (optional)
	if reader.NextTagIs(tlv.TLV_PUB_KEY) {
		pubKey, err = reader.ReadPrimitive(tlv.TLV_PUB_KEY)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key: %w", err)
		}
	}

	if reader.NextTagIs(tlv.TLV_PRIV_KEY) {
		privKey, err = reader.ReadPrimitive(tlv.TLV_PRIV_KEY)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %w", err)
		}
	}

	if reader.NextTagIs(tlv.TLV_CHAIN_CODE) {
		chainCode, err = reader.ReadPrimitive(tlv.TLV_CHAIN_CODE)
		if err != nil {
			return nil, fmt.Errorf("failed to read chain code: %w", err)
		}
	}

	return newBip32KeyPair(privKey, chainCode, pubKey), nil
}

func newBip32KeyPair(privateKey, chainCode, publicKey []byte) *Bip32KeyPair {
	var pubKey []byte
	if privateKey != nil && publicKey == nil {
		// Derive public key from private key
		stripped := stripLeadingZero(privateKey)
		priv := secp256k1.PrivKeyFromBytes(stripped)
		if priv != nil {
			pubKey = priv.PubKey().SerializeCompressed()
		}
	} else if publicKey != nil {
		pubKey = publicKey
	}

	return &Bip32KeyPair{
		privateKey: privateKey,
		chainCode:  chainCode,
		publicKey:  pubKey,
	}
}

// stripLeadingZero removes a leading zero byte from a private key if present.
func stripLeadingZero(pk []byte) []byte {
	if len(pk) > 32 && pk[0] == 0 {
		return pk[1:]
	}
	return pk
}

// ToTLV serializes to TLV format.
func (k *Bip32KeyPair) ToTLV(includePublic bool) []byte {
	writer := tlv.NewBerTlvWriter()
	writer.WriteConstructed(tlv.TLV_KEY_TEMPLATE, func(w *tlv.BerTlvWriter) {
		if includePublic && len(k.publicKey) > 0 {
			w.WritePrimitive(tlv.TLV_PUB_KEY, k.publicKey)
		}
		if k.privateKey != nil {
			w.WritePrimitive(tlv.TLV_PRIV_KEY, stripLeadingZero(k.privateKey))
		}
		if k.chainCode != nil {
			w.WritePrimitive(tlv.TLV_CHAIN_CODE, k.chainCode)
		}
	})
	return writer.ToBytes()
}

// ToEthereumAddress returns the Ethereum address of the public key.
func (k *Bip32KeyPair) ToEthereumAddress() [20]byte {
	return ToEthereumAddress(k.publicKey)
}

// PrivateKey returns the private key, or nil if not present.
// Note: returns the internal slice directly so that Zeroize() clears it.
func (k *Bip32KeyPair) PrivateKey() []byte {
	return k.privateKey
}

// ChainCode returns a copy of the chain code, or nil if not present.
func (k *Bip32KeyPair) ChainCode() []byte {
	if k.chainCode == nil {
		return nil
	}
	cp := make([]byte, len(k.chainCode))
	copy(cp, k.chainCode)
	return cp
}

// PublicKey returns the public key.
func (k *Bip32KeyPair) PublicKey() []byte {
	return k.publicKey
}

// IsPublicOnly returns true if only the public key is present (no private key).
func (k *Bip32KeyPair) IsPublicOnly() bool {
	return k.privateKey == nil
}

// IsExtended returns true if the key has a chain code (extended key).
func (k *Bip32KeyPair) IsExtended() bool {
	return k.chainCode != nil
}

// Zeroize clears the private key and chain code from memory.
func (k *Bip32KeyPair) Zeroize() {
	if k.privateKey != nil {
		crypto.Zeroize(k.privateKey)
		k.privateKey = nil
	}
	if k.chainCode != nil {
		crypto.Zeroize(k.chainCode)
		k.chainCode = nil
	}
}
