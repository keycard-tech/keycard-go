package crypto

import (
	"testing"

	"github.com/keycard-tech/keycard-go/v4/hexutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 4493 appendix A sample values, key 2b7e151628aed2a6abf7158809cf4f3c.
func TestCMAC(t *testing.T) {
	block := hexutils.MustHexToBytes("6bc1bee22e409f96e93d7e117393172a")

	tests := []struct {
		name     string
		key      string
		data     []byte
		expected string
	}{
		{"aes128 empty", "2b7e151628aed2a6abf7158809cf4f3c", nil, "BB1D6929E95937287FA37D129B756746"},
		{"aes128 one block", "2b7e151628aed2a6abf7158809cf4f3c", block, "070A16B46B4D4144F79BDD9DD04A287C"},
		{"aes128 partial last block", "2b7e151628aed2a6abf7158809cf4f3c", append(append([]byte{}, block...), hexutils.MustHexToBytes("ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411")...), "DFA66747DE9AE63030CA32611497C827"},
		{"aes128 four blocks", "2b7e151628aed2a6abf7158809cf4f3c", append(append(block, hexutils.MustHexToBytes("ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411")...), hexutils.MustHexToBytes("e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")...), "51F0BEBF7E3B9D92FC49741779363CFE"},
		{"aes192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", block, "9E99A7BF31E710900662F65E617C5184"},
		{"aes256", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", block, "28A7023F452E8F82BD4BF28D8C37C35C"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mac, err := CMAC(hexutils.MustHexToBytes(test.key), test.data)
			require.NoError(t, err)
			assert.Equal(t, test.expected, hexutils.BytesToHex(mac))
		})
	}
}

func TestCMAC_BadKeyLength(t *testing.T) {
	_, err := CMAC(make([]byte, 15), []byte{0x01})
	assert.Error(t, err)
}

// Session keys of the AES-128/S8 SCP03 fixture in Samsung/OpenSCP-Java,
// testdata/SmartCardScp03Aes128S8ModeEmulation.java, with host challenge
// 06F85B77251BF794 and card challenge 9CE033FA78E6B10D.
func TestDeriveSCP03Key(t *testing.T) {
	encKey := hexutils.MustHexToBytes("1D72CD9283FD55162722C6BEAA4DC187")
	macKey := hexutils.MustHexToBytes("F4932BA02FFC3098D172790099D28382")
	context := hexutils.MustHexToBytes("06F85B77251BF794" + "9CE033FA78E6B10D")

	tests := []struct {
		name     string
		key      []byte
		constant byte
		bits     int
		expected string
	}{
		{"S-ENC", encKey, DerivationConstantSENC, 128, "45AA38361C2D05306C4203B11A743AD9"},
		{"S-MAC", macKey, DerivationConstantSMAC, 128, "30BA0D745A51F10D717A086C11EE1FA0"},
		{"S-RMAC", macKey, DerivationConstantSRMAC, 128, "B72AF42E308A2E2CAAB8983CA7228778"},
		{"card cryptogram", hexutils.MustHexToBytes("30BA0D745A51F10D717A086C11EE1FA0"), DerivationConstantCardCryptogram, 64, "DC2DBE8974C8B0DE"},
		{"host cryptogram", hexutils.MustHexToBytes("30BA0D745A51F10D717A086C11EE1FA0"), DerivationConstantHostCryptogram, 64, "B08D6CE26B6CB3CC"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			derived, err := DeriveSCP03Key(test.key, test.constant, context, test.bits)
			require.NoError(t, err)
			assert.Equal(t, test.expected, hexutils.BytesToHex(derived))
		})
	}
}

// Keys longer than a CMAC block need the second KDF iteration.
func TestDeriveSCP03Key_AES256(t *testing.T) {
	key := hexutils.MustHexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")

	derived, err := DeriveSCP03Key(key, DerivationConstantSENC, make([]byte, 16), 256)
	require.NoError(t, err)
	assert.Equal(t, "A7C29A96DB87BEE1B8BE5BE928E1F00A22FBAE8ADD5085686EBCEA953719777B", hexutils.BytesToHex(derived))
}

func TestDeriveSCP03Key_BadLength(t *testing.T) {
	_, err := DeriveSCP03Key(make([]byte, 16), DerivationConstantSENC, make([]byte, 16), 100)
	assert.Error(t, err)
}

func TestPadISO9797M2(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		expected  string
	}{
		{"empty", nil, 16, "80000000000000000000000000000000"},
		{"partial", hexutils.MustHexToBytes("AABB"), 16, "AABB8000000000000000000000000000"},
		{"one byte short", hexutils.MustHexToBytes("0102030405060708090A0B0C0D0E0F"), 16, "0102030405060708090A0B0C0D0E0F80"},
		{"full block", hexutils.MustHexToBytes("0102030405060708090A0B0C0D0E0F10"), 16, "0102030405060708090A0B0C0D0E0F1080000000000000000000000000000000"},
		{"des block", hexutils.MustHexToBytes("AABB"), 8, "AABB800000000000"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, hexutils.BytesToHex(PadISO9797M2(test.data, test.blockSize)))
		})
	}
}

func TestUnpadISO9797M2(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		blockSize int
		expected  string
	}{
		{"full block padding", "80000000000000000000000000000000", 16, ""},
		{"one byte", "01800000000000000000000000000000", 16, "01"},
		{"no padding byte needed", "0102030405060708090A0B0C0D0E0F80", 16, "0102030405060708090A0B0C0D0E0F"},
		{"two blocks", "0102030405060708090A0B0C0D0E0F1080000000000000000000000000000000", 16, "0102030405060708090A0B0C0D0E0F10"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			unpadded, err := UnpadISO9797M2(hexutils.MustHexToBytes(test.data), test.blockSize)
			require.NoError(t, err)
			assert.Equal(t, test.expected, hexutils.BytesToHex(unpadded))
		})
	}
}

func TestUnpadISO9797M2_BadPadding(t *testing.T) {
	tests := []string{
		"",
		"0102",
		"0102030405060708090A0B0C0D0E0F11",
		"0102030405060708090A0B0C0D0E0F00",
	}

	for _, data := range tests {
		_, err := UnpadISO9797M2(hexutils.MustHexToBytes(data), 16)
		assert.ErrorIs(t, err, ErrBadPadding, data)
	}
}

// FIPS-197 example vector, the primitive of the SCP03 ICV derivation.
func TestEncryptAESBlock(t *testing.T) {
	encrypted, err := EncryptAESBlock(hexutils.MustHexToBytes("000102030405060708090a0b0c0d0e0f"), hexutils.MustHexToBytes("00112233445566778899aabbccddeeff"))
	require.NoError(t, err)
	assert.Equal(t, "69C4E0D86A7B0430D8CDB78070B4C55A", hexutils.BytesToHex(encrypted))

	_, err = EncryptAESBlock(hexutils.MustHexToBytes("2b7e151628aed2a6abf7158809cf4f3c"), []byte{0x01})
	assert.Error(t, err)
}

func TestAESCBC(t *testing.T) {
	key := hexutils.MustHexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
	iv := hexutils.MustHexToBytes("000102030405060708090a0b0c0d0e0f")
	data := hexutils.MustHexToBytes("6bc1bee22e409f96e93d7e117393172a")

	encrypted, err := EncryptAESCBC(key, iv, data)
	require.NoError(t, err)

	decrypted, err := DecryptAESCBC(key, iv, encrypted)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestAESCBC_BadData(t *testing.T) {
	key := hexutils.MustHexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
	iv := make([]byte, 16)

	_, err := EncryptAESCBC(key, iv, nil)
	assert.Error(t, err)

	_, err = EncryptAESCBC(key, iv, []byte{0x01})
	assert.Error(t, err)
}
