package crypto

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// NewCCM tests
// ============================================================================

func TestNewCCM_Valid(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	// Valid nonce lengths: 7..13
	for nonceLen := 7; nonceLen <= 13; nonceLen++ {
		for _, tagLen := range []int{4, 6, 8, 12, 16} {
			ccm, err := NewCCM(block, nonceLen, tagLen)
			require.NoError(t, err, "nonceLen=%d, tagLen=%d", nonceLen, tagLen)
			assert.NotNil(t, ccm)
			assert.Equal(t, nonceLen, ccm.nonceLen)
			assert.Equal(t, tagLen, ccm.tagLen)
		}
	}
}

func TestNewCCM_InvalidNonceLength(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)

	for _, nonceLen := range []int{0, 1, 6, 14, 16} {
		_, err := NewCCM(block, nonceLen, 8)
		assert.Error(t, err, "nonceLen=%d should fail", nonceLen)
		assert.Contains(t, err.Error(), "invalid nonce length")
	}
}

func TestNewCCM_InvalidTagLength(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)

	for _, tagLen := range []int{0, 1, 2, 3, 5, 7, 10, 15, 20} {
		_, err := NewCCM(block, 13, tagLen)
		assert.Error(t, err, "tagLen=%d should fail", tagLen)
		assert.Contains(t, err.Error(), "invalid tag length")
	}
}

// ============================================================================
// EncryptAndAuthenticate / DecryptAndAuthenticate round-trip tests
// ============================================================================

func TestCCM_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		nonceLen int
		tagLen   int
	}{
		{"nonce13_tag4", 13, 4},
		{"nonce13_tag8", 13, 8},
		{"nonce13_tag16", 13, 16},
		{"nonce13_tag12", 13, 12},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ccm, err := NewCCM(block, tc.nonceLen, tc.tagLen)
			require.NoError(t, err)

			nonce := make([]byte, tc.nonceLen)
			for i := range nonce {
				nonce[i] = byte(i + 1)
			}

			plaintext := []byte("Hello, AES-CCM world! This is a test message.")

			ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext, nil)
			require.NoError(t, err)
			assert.Equal(t, len(plaintext)+tc.tagLen, len(ciphertext))

			decrypted, err := ccm.DecryptAndAuthenticate(nonce, ciphertext, nil)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

func TestCCM_RoundTrip_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	ccm, err := NewCCM(block, 13, 8)
	require.NoError(t, err)

	nonce := make([]byte, 13)
	plaintext := []byte{}

	ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext, nil)
	require.NoError(t, err)
	assert.Equal(t, 8, len(ciphertext)) // only tag

	decrypted, err := ccm.DecryptAndAuthenticate(nonce, ciphertext, nil)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestCCM_RoundTrip_WithAAD(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	ccm, err := NewCCM(block, 13, 8)
	require.NoError(t, err)

	nonce := make([]byte, 13)
	plaintext := []byte("Secret message")
	aad := []byte("Additional authenticated data")

	ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext, aad)
	require.NoError(t, err)

	decrypted, err := ccm.DecryptAndAuthenticate(nonce, ciphertext, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestCCM_Authentication_FailsWithWrongAAD(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	ccm, err := NewCCM(block, 13, 8)
	require.NoError(t, err)

	nonce := make([]byte, 13)
	plaintext := []byte("Secret message")
	aad := []byte("Correct AAD")
	wrongAAD := []byte("Wrong AAD")

	ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext, aad)
	require.NoError(t, err)

	_, err = ccm.DecryptAndAuthenticate(nonce, ciphertext, wrongAAD)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestCCM_Authentication_FailsWithTamperedCiphertext(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	ccm, err := NewCCM(block, 13, 8)
	require.NoError(t, err)

	nonce := make([]byte, 13)
	plaintext := []byte("Secret message")

	ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext, nil)
	require.NoError(t, err)

	// Tamper with a byte in the ciphertext (not the tag)
	ciphertext[0] ^= 0xFF

	_, err = ccm.DecryptAndAuthenticate(nonce, ciphertext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestCCM_Authentication_FailsWithWrongNonce(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	ccm, err := NewCCM(block, 13, 8)
	require.NoError(t, err)

	nonce := make([]byte, 13)
	wrongNonce := make([]byte, 13)
	wrongNonce[0] = 0xFF
	plaintext := []byte("Secret message")

	ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext, nil)
	require.NoError(t, err)

	_, err = ccm.DecryptAndAuthenticate(wrongNonce, ciphertext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestCCM_InvalidNonceLength(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	ccm, err := NewCCM(block, 13, 8)
	require.NoError(t, err)

	plaintext := []byte("test")
	shortNonce := make([]byte, 12)
	longNonce := make([]byte, 14)

	_, err = ccm.EncryptAndAuthenticate(shortNonce, plaintext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce length")

	_, err = ccm.EncryptAndAuthenticate(longNonce, plaintext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce length")

	ciphertext, _ := ccm.EncryptAndAuthenticate(make([]byte, 13), plaintext, nil)
	_, err = ccm.DecryptAndAuthenticate(shortNonce, ciphertext, nil)
	assert.Error(t, err)
}

func TestCCM_PlaintextTooLong(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	ccm, err := NewCCM(block, 13, 8)
	require.NoError(t, err)

	nonce := make([]byte, 13)
	plaintext := make([]byte, 0xFFFE+1) // 65535 bytes, exceeds max

	_, err = ccm.EncryptAndAuthenticate(nonce, plaintext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

func TestCCM_CiphertextTooShort(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	ccm, err := NewCCM(block, 13, 8)
	require.NoError(t, err)

	nonce := make([]byte, 13)
	shortCiphertext := make([]byte, 4) // shorter than tag length

	_, err = ccm.DecryptAndAuthenticate(nonce, shortCiphertext, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestCCM_LargePlaintext(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	ccm, err := NewCCM(block, 13, 8)
	require.NoError(t, err)

	nonce := make([]byte, 13)
	plaintext := make([]byte, 1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext, nil)
	require.NoError(t, err)

	decrypted, err := ccm.DecryptAndAuthenticate(nonce, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// ============================================================================
// AESCCMEncrypt / AESCCMDecrypt convenience function tests
// ============================================================================

func TestAESCCMEncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 13)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}

	plaintext := []byte("Testing AES-128-CCM convenience functions")

	ciphertext, err := AESCCMEncrypt(key, nonce, plaintext)
	require.NoError(t, err)
	assert.Equal(t, len(plaintext)+8, len(ciphertext))

	decrypted, err := AESCCMDecrypt(key, nonce, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESCCMEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 13)

	ciphertext, err := AESCCMEncrypt(key, nonce, []byte{})
	require.NoError(t, err)
	assert.Equal(t, 8, len(ciphertext))

	decrypted, err := AESCCMDecrypt(key, nonce, ciphertext)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestAESCCMEncrypt_InvalidKeyLength(t *testing.T) {
	nonce := make([]byte, 13)

	_, err := AESCCMEncrypt([]byte("short"), nonce, []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key must be 16 bytes")
}

func TestAESCCMEncrypt_InvalidNonceLength(t *testing.T) {
	key := make([]byte, 16)

	_, err := AESCCMEncrypt(key, []byte("short"), []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce must be 13 bytes")
}

func TestAESCCMDecrypt_InvalidKeyLength(t *testing.T) {
	nonce := make([]byte, 13)

	_, err := AESCCMDecrypt([]byte("short"), nonce, []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key must be 16 bytes")
}

func TestAESCCMDecrypt_InvalidNonceLength(t *testing.T) {
	key := make([]byte, 16)

	_, err := AESCCMDecrypt(key, []byte("short"), []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce must be 13 bytes")
}

func TestAESCCMDecrypt_AuthenticationFailure(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 13)

	plaintext := []byte("test data")
	ciphertext, err := AESCCMEncrypt(key, nonce, plaintext)
	require.NoError(t, err)

	// Tamper with ciphertext
	ciphertext[0] ^= 0xFF

	_, err = AESCCMDecrypt(key, nonce, ciphertext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

// ============================================================================
// HKDFDerive tests
// ============================================================================

func TestHKDFDerive_Basic(t *testing.T) {
	// Simple self-consistency test: derive keys and verify they are deterministic
	ikm := []byte("input keying material")
	salt := []byte("00 01 02 03 04 05 06 07 08 09 0a 0b 0c")
	info := []byte("f0 f1 f2 f3 f4 f5 f6 f7 f8 f9")

	okm, err := HKDFDerive(info, salt, ikm, 42)
	require.NoError(t, err)
	assert.Len(t, okm, 42)

	// Verify determinism
	okm2, err := HKDFDerive(info, salt, ikm, 42)
	require.NoError(t, err)
	assert.Equal(t, okm, okm2)
}

func TestHKDFDerive_NoSalt(t *testing.T) {
	ikm := []byte("input keying material")
	info := []byte("context info")

	okm, err := HKDFDerive(info, nil, ikm, 32)
	require.NoError(t, err)
	assert.Len(t, okm, 32)
}

func TestHKDFDerive_VariousLengths(t *testing.T) {
	ikm := []byte("key material")
	salt := []byte("salt value")
	info := []byte("info")

	for _, length := range []int{16, 32, 48, 64} {
		okm, err := HKDFDerive(info, salt, ikm, length)
		require.NoError(t, err, "length=%d", length)
		assert.Len(t, okm, length)
	}
}

func TestHKDFDerive_Deterministic(t *testing.T) {
	ikm := []byte("same input")
	salt := []byte("same salt")
	info := []byte("same info")

	okm1, err := HKDFDerive(info, salt, ikm, 32)
	require.NoError(t, err)

	okm2, err := HKDFDerive(info, salt, ikm, 32)
	require.NoError(t, err)

	assert.Equal(t, okm1, okm2)
}

func TestHKDFDerive_DifferentInfo(t *testing.T) {
	ikm := []byte("same input")
	salt := []byte("same salt")
	info1 := []byte("info 1")
	info2 := []byte("info 2")

	okm1, err := HKDFDerive(info1, salt, ikm, 32)
	require.NoError(t, err)

	okm2, err := HKDFDerive(info2, salt, ikm, 32)
	require.NoError(t, err)

	assert.NotEqual(t, okm1, okm2)
}
