package derivationpath

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyPathFromStringMaster(t *testing.T) {
	kp, err := KeyPathFromString("m/44'/0'/0'/0/0")
	require.NoError(t, err)
	assert.Equal(t, SourceMaster, kp.Source())
	assert.Equal(t, 20, len(kp.Data())) // 5 components * 4 bytes

	// Check first component: 44' = 0x8000002C
	assert.Equal(t, byte(0x80), kp.Data()[0])
	assert.Equal(t, byte(0x00), kp.Data()[1])
	assert.Equal(t, byte(0x00), kp.Data()[2])
	assert.Equal(t, byte(0x2C), kp.Data()[3])
}

func TestKeyPathFromStringParent(t *testing.T) {
	kp, err := KeyPathFromString("../0/1")
	require.NoError(t, err)
	assert.Equal(t, SourceParent, kp.Source())
}

func TestKeyPathFromStringCurrent(t *testing.T) {
	kp, err := KeyPathFromString("./0/1")
	require.NoError(t, err)
	assert.Equal(t, SourceCurrent, kp.Source())
}

func TestKeyPathFromStringImplicitCurrent(t *testing.T) {
	kp, err := KeyPathFromString("0/1/2")
	require.NoError(t, err)
	assert.Equal(t, SourceCurrent, kp.Source())
}

func TestKeyPathFromStringSingleComponent(t *testing.T) {
	kp, err := KeyPathFromString("m/0")
	require.NoError(t, err)
	assert.Equal(t, 4, len(kp.Data()))
}

func TestKeyPathStringRoundtrip(t *testing.T) {
	testCases := []string{
		"m/44'/0'/0'/0/0",
		"./1/2/3'",
		"../0/1",
		"m/0",
		"m/44'/0'",
	}

	for _, tc := range testCases {
		kp, err := KeyPathFromString(tc)
		require.NoError(t, err, "failed to parse: %s", tc)
		assert.Equal(t, tc, kp.String(), "roundtrip failed for: %s", tc)
	}
}

func TestKeyPathFromStringTooManyComponents(t *testing.T) {
	_, err := KeyPathFromString("m/0/1/2/3/4/5/6/7/8/9/10")
	assert.Error(t, err)
}

func TestKeyPathFromStringSignedComponent(t *testing.T) {
	_, err := KeyPathFromString("m/+44")
	assert.Error(t, err)

	_, err = KeyPathFromString("m/-44")
	assert.Error(t, err)
}

func TestKeyPathFromStringInvalidNumber(t *testing.T) {
	_, err := KeyPathFromString("m/abc")
	assert.Error(t, err)
}

func TestKeyPathFromRaw(t *testing.T) {
	kp := KeyPathFromRaw([]byte{0x80, 0x00, 0x00, 0x2C}, SourceMaster)
	assert.Equal(t, SourceMaster, kp.Source())
	assert.Equal(t, []byte{0x80, 0x00, 0x00, 0x2C}, kp.Data())
}

func TestKeyPathFromRawMaster(t *testing.T) {
	kp := KeyPathFromRawMaster([]byte{0x00, 0x00, 0x00, 0x00})
	assert.Equal(t, SourceMaster, kp.Source())
}

func TestKeyPathFromStringEmpty(t *testing.T) {
	_, err := KeyPathFromString("")
	assert.Error(t, err)
}
