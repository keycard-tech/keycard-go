package types

import (
	"fmt"

	"github.com/keycard-tech/keycard-go/v4/tlv"
)

// LeeSecretSize is the size of a LEE secret in bytes (each ASK/NSK/VSK
// component is 32 bytes).
const LeeSecretSize = 32

// LeeKey is the parsed LEE key material from an EXPORT LEE response.
//
// The applet's EXPORT LEE command returns a constructed TLV_KEY_TEMPLATE
// containing four 32-byte primitive values, per the LEE-Keys v1 derivation
// scheme:
//
//   - TLV_LEE_ASK (0x84) — authorization secret key
//   - TLV_LEE_NSK (0x83) — nullifier secret key
//   - TLV_LEE_VSK_D (0x85) — viewing seed (diversifier)
//   - TLV_LEE_VSK_Z (0x86) — viewing seed (nullifier)
type LeeKey struct {
	ask  [LeeSecretSize]byte
	nsk  [LeeSecretSize]byte
	vskD [LeeSecretSize]byte
	vskZ [LeeSecretSize]byte
}

// ASK returns the authorization secret key.
func (k *LeeKey) ASK() [LeeSecretSize]byte {
	return k.ask
}

// NSK returns the nullifier secret key.
func (k *LeeKey) NSK() [LeeSecretSize]byte {
	return k.nsk
}

// VSKD returns the viewing seed diversifier.
func (k *LeeKey) VSKD() [LeeSecretSize]byte {
	return k.vskD
}

// VSKZ returns the viewing seed nullifier.
func (k *LeeKey) VSKZ() [LeeSecretSize]byte {
	return k.vskZ
}

// ParseLeeKey parses the TLV response from an EXPORT LEE command.
//
// The response is a constructed TLV_KEY_TEMPLATE containing, in order: ASK
// (0x84), NSK (0x83), VSK_D (0x85) and VSK_Z (0x86), each 32 bytes.
//
// Returns an error if the response is malformed or any component is not
// exactly 32 bytes long.
func ParseLeeKey(data []byte) (*LeeKey, error) {
	r := tlv.NewBerTlvReader(data)

	tpl, err := r.ReadPrimitive(tlv.TLV_KEY_TEMPLATE)
	if err != nil {
		return nil, fmt.Errorf("failed to enter LEE key template: %w", err)
	}

	inner := tlv.NewBerTlvReader(tpl)

	ask, err := readLeeSecret(inner, tlv.TLV_LEE_ASK, "ASK")
	if err != nil {
		return nil, err
	}
	nsk, err := readLeeSecret(inner, tlv.TLV_LEE_NSK, "NSK")
	if err != nil {
		return nil, err
	}
	vskD, err := readLeeSecret(inner, tlv.TLV_LEE_VSK_D, "VSK_D")
	if err != nil {
		return nil, err
	}
	vskZ, err := readLeeSecret(inner, tlv.TLV_LEE_VSK_Z, "VSK_Z")
	if err != nil {
		return nil, err
	}

	return &LeeKey{ask: ask, nsk: nsk, vskD: vskD, vskZ: vskZ}, nil
}

// readLeeSecret reads a 32-byte primitive secret with the given tag.
func readLeeSecret(reader *tlv.BerTlvReader, tag uint8, name string) ([LeeSecretSize]byte, error) {
	var result [LeeSecretSize]byte

	value, err := reader.ReadPrimitive(tag)
	if err != nil {
		return result, fmt.Errorf("failed to read LEE %s (0x%02X): %w", name, tag, err)
	}

	if len(value) != LeeSecretSize {
		return result, fmt.Errorf(
			"LEE %s must be exactly %d bytes, got %d",
			name, LeeSecretSize, len(value),
		)
	}

	copy(result[:], value)
	return result, nil
}
