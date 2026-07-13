package types

import (
	"golang.org/x/crypto/sha3"
)

// ToEthereumAddress computes an Ethereum address from a public key.
// Takes Keccak-256 of the public key bytes starting from index 1
// (skipping the 0x02/0x03/0x04 prefix) and returns the last 20 bytes.
//
// publicKey should be an uncompressed secp256k1 public key (65 bytes, starting with 0x04)
// or a compressed key (33 bytes).
func ToEthereumAddress(publicKey []byte) [20]byte {
	var addr [20]byte
	if len(publicKey) < 2 {
		return addr
	}

	keccak := sha3.NewLegacyKeccak256()
	keccak.Write(publicKey[1:])
	hash := keccak.Sum(nil)

	// Take last 20 bytes
	copy(addr[:], hash[12:])
	return addr
}
