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

	ccm := NewCCM(block)
	assert.NotNil(t, ccm)
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

	ccm := NewCCM(block)
	nonce := make([]byte, ccmNonceLen)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}

	plaintext := []byte("Hello, AES-CCM world! This is a test message.")

	ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext)
	require.NoError(t, err)
	assert.Equal(t, len(plaintext)+ccmTagLen, len(ciphertext))

	decrypted, err := ccm.DecryptAndAuthenticate(nonce, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestCCM_RoundTrip_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	ccm := NewCCM(block)
	nonce := make([]byte, ccmNonceLen)
	plaintext := []byte{}

	ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext)
	require.NoError(t, err)
	assert.Equal(t, ccmTagLen, len(ciphertext)) // only tag

	decrypted, err := ccm.DecryptAndAuthenticate(nonce, ciphertext)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestCCM_Authentication_FailsWithTamperedCiphertext(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	ccm := NewCCM(block)
	nonce := make([]byte, ccmNonceLen)
	plaintext := []byte("Secret message")

	ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext)
	require.NoError(t, err)

	// Tamper with a byte in the ciphertext (not the tag)
	ciphertext[0] ^= 0xFF

	_, err = ccm.DecryptAndAuthenticate(nonce, ciphertext)
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

	ccm := NewCCM(block)
	nonce := make([]byte, ccmNonceLen)
	wrongNonce := make([]byte, ccmNonceLen)
	wrongNonce[0] = 0xFF
	plaintext := []byte("Secret message")

	ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext)
	require.NoError(t, err)

	_, err = ccm.DecryptAndAuthenticate(wrongNonce, ciphertext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestCCM_InvalidNonceLength(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	ccm := NewCCM(block)

	plaintext := []byte("test")
	shortNonce := make([]byte, 12)
	longNonce := make([]byte, 14)

	_, err := ccm.EncryptAndAuthenticate(shortNonce, plaintext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce length")

	_, err = ccm.EncryptAndAuthenticate(longNonce, plaintext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce length")

	ciphertext, _ := ccm.EncryptAndAuthenticate(make([]byte, ccmNonceLen), plaintext)
	_, err = ccm.DecryptAndAuthenticate(shortNonce, ciphertext)
	assert.Error(t, err)
}

func TestCCM_PlaintextTooLong(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	ccm := NewCCM(block)

	nonce := make([]byte, ccmNonceLen)
	plaintext := make([]byte, 0xFFFE+1) // 65535 bytes, exceeds max

	_, err := ccm.EncryptAndAuthenticate(nonce, plaintext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

func TestCCM_CiphertextTooShort(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	ccm := NewCCM(block)

	nonce := make([]byte, ccmNonceLen)
	shortCiphertext := make([]byte, 4) // shorter than tag length

	_, err := ccm.DecryptAndAuthenticate(nonce, shortCiphertext)
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

	ccm := NewCCM(block)
	nonce := make([]byte, ccmNonceLen)
	plaintext := make([]byte, 1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := ccm.EncryptAndAuthenticate(nonce, plaintext)
	require.NoError(t, err)

	decrypted, err := ccm.DecryptAndAuthenticate(nonce, ciphertext)
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
