package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMnemonicFromCardResponse(t *testing.T) {
	// 12 words = 24 bytes (2 bytes per index)
	data := make([]byte, 24)
	for i := 0; i < 12; i++ {
		data[i*2] = byte(i >> 8)
		data[i*2+1] = byte(i)
	}
	mnemonic := MnemonicFromCardResponse(data)
	assert.Equal(t, 12, len(mnemonic.Indexes()))
	for i, idx := range mnemonic.Indexes() {
		assert.Equal(t, uint16(i), idx)
	}
}

func TestMnemonicWordsWithBIP39English(t *testing.T) {
	mnemonic := MnemonicFromCardResponse([]byte{0x00, 0x00, 0x00, 0x01})
	words := mnemonic.Words()
	require.Len(t, words, 2)
	assert.Equal(t, "abandon", words[0])
	assert.Equal(t, "ability", words[1])
}

func TestMnemonicToPhrase(t *testing.T) {
	mnemonic := MnemonicFromCardResponse([]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x02})
	phrase := mnemonic.ToPhrase()
	assert.Equal(t, "abandon ability able", phrase)
}

func TestMnemonicBinarySeedFromPhrase(t *testing.T) {
	// BIP39 mnemonic-to-seed test vector
	phrase := "legal winner thank year wave sausage worth useful legal winner thank yellow"
	seed := BinarySeedFromPhrase(phrase, "")
	// Verified against python-mnemonic library output
	expectedHex := "878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096"
	expected := hexDecode(expectedHex)
	assert.Equal(t, expected, seed)
}

func TestMnemonicToSeed(t *testing.T) {
	mnemonic := MnemonicFromCardResponse([]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x02})
	seed := mnemonic.ToSeed("")
	assert.Equal(t, 64, len(seed))
}

func TestMnemonicToBinarySeed(t *testing.T) {
	mnemonic := MnemonicFromCardResponse([]byte{0x00, 0x00})
	seed := mnemonic.ToBinarySeed()
	assert.Equal(t, 64, len(seed))
}

func TestMnemonicToBIP32KeyPair(t *testing.T) {
	mnemonic := MnemonicFromCardResponse([]byte{0x00, 0x00, 0x00, 0x01})
	kp := mnemonic.ToBIP32KeyPair()
	assert.NotNil(t, kp)
	assert.NotNil(t, kp.PrivateKey())
	assert.NotNil(t, kp.ChainCode())
}

func TestMnemonicFromIndices(t *testing.T) {
	mnemonic, err := MnemonicFromIndices([]int16{0, 1, 2})
	require.NoError(t, err)
	words := mnemonic.Words()
	require.Len(t, words, 3)
	assert.Equal(t, "abandon", words[0])
	assert.Equal(t, "ability", words[1])
	assert.Equal(t, "able", words[2])
}

func TestMnemonicFromIndicesInvalid(t *testing.T) {
	_, err := MnemonicFromIndices([]int16{2048})
	assert.Error(t, err)

	_, err = MnemonicFromIndices([]int16{-1})
	assert.Error(t, err)
}

func TestBIP39EnglishWordlistSize(t *testing.T) {
	assert.Equal(t, 2048, len(BIP39EnglishWordlist))
}
