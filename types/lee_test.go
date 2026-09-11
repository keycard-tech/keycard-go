package types

import (
	"testing"

	"github.com/keycard-tech/keycard-go/v4/hexutils"
	"github.com/keycard-tech/keycard-go/v4/tlv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLeeKey(t *testing.T) {
	ask := [32]byte{0x7B}
	nsk := [32]byte{0xEF}
	vskD := [32]byte{0x9B}
	vskZ := [32]byte{0xBF}

	writer := tlv.NewBerTlvWriter()
	writer.WriteConstructed(tlv.TLV_KEY_TEMPLATE, func(w *tlv.BerTlvWriter) {
		w.WritePrimitive(tlv.TLV_LEE_ASK, ask[:])
		w.WritePrimitive(tlv.TLV_LEE_NSK, nsk[:])
		w.WritePrimitive(tlv.TLV_LEE_VSK_D, vskD[:])
		w.WritePrimitive(tlv.TLV_LEE_VSK_Z, vskZ[:])
	})

	key, err := ParseLeeKey(writer.ToBytes())
	require.NoError(t, err)
	assert.Equal(t, ask, key.ASK())
	assert.Equal(t, nsk, key.NSK())
	assert.Equal(t, vskD, key.VSKD())
	assert.Equal(t, vskZ, key.VSKZ())
}

func TestParseLeeKeyMissingComponent(t *testing.T) {
	writer := tlv.NewBerTlvWriter()
	writer.WriteConstructed(tlv.TLV_KEY_TEMPLATE, func(w *tlv.BerTlvWriter) {
		w.WritePrimitive(tlv.TLV_LEE_ASK, make([]byte, 32))
		// NSK missing
		w.WritePrimitive(tlv.TLV_LEE_VSK_D, make([]byte, 32))
		w.WritePrimitive(tlv.TLV_LEE_VSK_Z, make([]byte, 32))
	})

	_, err := ParseLeeKey(writer.ToBytes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NSK")
}

func TestParseLeeKeyWrongSize(t *testing.T) {
	writer := tlv.NewBerTlvWriter()
	writer.WriteConstructed(tlv.TLV_KEY_TEMPLATE, func(w *tlv.BerTlvWriter) {
		w.WritePrimitive(tlv.TLV_LEE_ASK, make([]byte, 16)) // too short
		w.WritePrimitive(tlv.TLV_LEE_NSK, make([]byte, 32))
		w.WritePrimitive(tlv.TLV_LEE_VSK_D, make([]byte, 32))
		w.WritePrimitive(tlv.TLV_LEE_VSK_Z, make([]byte, 32))
	})

	_, err := ParseLeeKey(writer.ToBytes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ASK")
	assert.Contains(t, err.Error(), "32")
}

func TestParseLeeKeyNotConstructed(t *testing.T) {
	// Not wrapped in a key template
	writer := tlv.NewBerTlvWriter()
	writer.WritePrimitive(tlv.TLV_LEE_ASK, make([]byte, 32))

	_, err := ParseLeeKey(writer.ToBytes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LEE key template")
}

func TestLeeKeyKnownVector(t *testing.T) {
	// Test vector from the applet's LEE Keys test (LEE-Keys v1).
	ask := hexutils.MustHexToBytes("7b9530590b74199ec623fd74bedc5b981c8eb36205f9981980f80c7cefc99d7d")
	nsk := hexutils.MustHexToBytes("ef2b7994d905e72109f60de69ee212f82ed3b99d261916671337a8b744f7a515")
	vskD := hexutils.MustHexToBytes("9bbdfc6def553c24cd50755f8c45e120a2210e66f8a3d2d2487d591158fe7439")
	vskZ := hexutils.MustHexToBytes("bfabaa3ab7f9537b11035f6f1d31a3e9d2e85249f7e42e3053386c0b14b1384e")

	var askArr, nskArr, vskDArr, vskZArr [LeeSecretSize]byte
	copy(askArr[:], ask)
	copy(nskArr[:], nsk)
	copy(vskDArr[:], vskD)
	copy(vskZArr[:], vskZ)

	writer := tlv.NewBerTlvWriter()
	writer.WriteConstructed(tlv.TLV_KEY_TEMPLATE, func(w *tlv.BerTlvWriter) {
		w.WritePrimitive(tlv.TLV_LEE_ASK, ask)
		w.WritePrimitive(tlv.TLV_LEE_NSK, nsk)
		w.WritePrimitive(tlv.TLV_LEE_VSK_D, vskD)
		w.WritePrimitive(tlv.TLV_LEE_VSK_Z, vskZ)
	})

	key, err := ParseLeeKey(writer.ToBytes())
	require.NoError(t, err)
	assert.Equal(t, askArr, key.ASK())
	assert.Equal(t, nskArr, key.NSK())
	assert.Equal(t, vskDArr, key.VSKD())
	assert.Equal(t, vskZArr, key.VSKZ())
}
