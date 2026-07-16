package types

import (
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/keycard-tech/keycard-go/v4/hexutils"
	"github.com/stretchr/testify/assert"
)

func TestVerifyIdentity(t *testing.T) {
	challenge := hexutils.MustHexToBytes("63acd6e02a8b5783551ff2836a9cbdf237c115c3ff018b943f044e6a69b19fe7")
	response := hexutils.MustHexToBytes("a081ab8a620365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a11188ada267db3312a84e1be27c01c736a89da7a1fe4f7e90ce297e74f00008e2bfdb06058374abfc1c026386d16ead7bbc19bc0645d2e7acf7b953169bbc1ac0130450220364c5ca937b7ca42861978f086d206cc569ef0bb2ea4c7de08929c2fcca7434d022100c87699ce4f977e6a7a4800343db9b6842b91ca873e56dfe3327d19a2d01af14e")
	expectedKey := hexutils.MustHexToBytes("02fc929321aa94fea085b166994aa66590116252cf0235a03accaa2c8ab4595de5")

	pubkey, err := VerifyIdentity(challenge, response)
	assert.NoError(t, err)
	assert.Equal(t, expectedKey, pubkey)
}

func TestGenerateIdentKeyPair(t *testing.T) {
	privKey, err := GenerateIdentKeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, privKey)
	assert.NotNil(t, privKey.PubKey())
	assert.Equal(t, 33, len(privKey.PubKey().SerializeCompressed()))
	assert.Equal(t, 32, len(privKey.Serialize()))
}

func TestGenerateNewCertificate(t *testing.T) {
	// Generate a CA keypair
	caPriv, err := secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)

	// Generate a new certificate
	cert, err := GenerateNewCertificate(caPriv)
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// Verify identity public key is 33 bytes compressed
	assert.Equal(t, 33, len(cert.IdentPub()))

	// Verify CA public key can be recovered
	caPub := caPriv.PubKey()
	assert.Equal(t, caPub.SerializeCompressed(), cert.CAPublicKey())

	// Verify private key is set
	assert.NotNil(t, cert.IdentPriv())
	assert.Equal(t, 32, len(cert.IdentPriv()))

	// Verify recID is valid
	assert.LessOrEqual(t, cert.RecID(), byte(3))
}

func TestCreateCertificate(t *testing.T) {
	// Generate CA keypair
	caPriv, err := secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)

	// Generate identity keypair
	identPriv, err := GenerateIdentKeyPair()
	assert.NoError(t, err)

	identPubBytes := identPriv.PubKey().SerializeCompressed()
	var identPub [33]byte
	copy(identPub[:], identPubBytes)

	// Create certificate
	cert, err := CreateCertificate(caPriv, identPub, identPriv.Serialize())
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// Verify identity public key matches
	assert.Equal(t, identPub, cert.IdentPub())

	// Verify CA public key
	assert.Equal(t, caPriv.PubKey().SerializeCompressed(), cert.CAPublicKey())

	// Verify private key
	assert.Equal(t, identPriv.Serialize(), cert.IdentPriv())
}

func TestToStoreData(t *testing.T) {
	// Generate CA keypair
	caPriv, err := secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)

	// Generate certificate
	cert, err := GenerateNewCertificate(caPriv)
	assert.NoError(t, err)

	// Serialize to store data
	storeData, err := cert.ToStoreData()
	assert.NoError(t, err)

	// Verify length: 33 (identPub) + 32 (r) + 32 (s) + 1 (recID) + 32 (identPriv) = 130
	assert.Equal(t, 130, len(storeData))

	// Verify components
	identPub := cert.IdentPub()
	assert.Equal(t, identPub[:], storeData[0:33])
	assert.Equal(t, cert.signature.r, storeData[33:65])
	assert.Equal(t, cert.signature.s, storeData[65:97])
	assert.Equal(t, cert.RecID(), storeData[97])
	assert.Equal(t, cert.IdentPriv(), storeData[98:130])
}

func TestToStoreDataNoPrivKey(t *testing.T) {
	// Parse a certificate from external data (no private key)
	// This is 98 bytes: 33 (pub) + 32 (r) + 32 (s) + 1 (recID)
	certData := hexutils.MustHexToBytes("0365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a11188ada267db3312a84e1be27c01c736a89da7a1fe4f7e90ce297e74f00008e2bfdb06058374abfc1c026386d16ead7bbc19bc0645d2e7acf7b953169bbc1ac01")
	cert, err := ParseCertificate(certData)
	assert.NoError(t, err)

	// ToStoreData should fail because private key is not set
	_, err = cert.ToStoreData()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key not set")
}

func TestCertificateRoundTrip(t *testing.T) {
	// Generate CA keypair
	caPriv, err := secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)

	// Generate certificate
	cert, err := GenerateNewCertificate(caPriv)
	assert.NoError(t, err)

	// Serialize to store data
	storeData, err := cert.ToStoreData()
	assert.NoError(t, err)

	// The first 98 bytes are the parseable certificate format
	parsedCert, err := ParseCertificate(storeData[0:98])
	assert.NoError(t, err)

	// Verify the parsed certificate has the same identity public key
	assert.Equal(t, cert.IdentPub(), parsedCert.IdentPub())

	// Verify the parsed certificate has the same CA public key
	assert.Equal(t, cert.CAPublicKey(), parsedCert.CAPublicKey())

	// Note: parsed certificate won't have the private key
	assert.Nil(t, parsedCert.IdentPriv())
}
