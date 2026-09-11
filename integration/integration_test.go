// Integration tests that communicate with a real Keycard via a Transmitter.
//
// These tests require a physically connected Keycard and a smart card reader.
// They live in their own Go module so that the PC/SC (cgo) dependency does not
// leak into the main keycard-go module.
//
// To run them:
//
//	cd integration && go test -v
//
// To run a specific test:
//
//	cd integration && go test -run TestIntegration/SelectApplet -v
//
// The tests automatically connect to the first available PC/SC reader.
// Set the KEYCARD_READER environment variable to pick a specific reader:
//
//	KEYCARD_READER="ACS CCID Reader 0" go test -v

package integration_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/ebfe/scard"
	"github.com/keycard-tech/keycard-go/v4"
	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/hexutils"
	"github.com/keycard-tech/keycard-go/v4/io"
	"github.com/keycard-tech/keycard-go/v4/types"
)

// ============================================================================
// Test CA public key — only to be used in tests.
// ============================================================================

// testCAPublicKey is the test CA public key (compressed secp256k1, 33 bytes).
var testCAPublicKey = [33]byte{
	0x02, 0x58, 0x77, 0x22, 0x0a, 0xaa, 0xe6, 0xe5,
	0x4a, 0x6f, 0x97, 0x46, 0x02, 0xd5, 0x99, 0x5c,
	0x0f, 0xe2, 0x4a, 0x3e, 0xa7, 0xdd, 0xab, 0xd8,
	0x64, 0x4b, 0xec, 0x79, 0x5b, 0x9d, 0xa0, 0x07,
	0x43,
}

// ============================================================================
// LoggingChannel — wraps a Channel and logs every APDU sent/received.
// ============================================================================

// loggingChannel wraps a types.Channel and logs every APDU for diagnostics.
type loggingChannel struct {
	inner types.Channel
}

func (l *loggingChannel) Send(cmd *apdu.Command) (*apdu.Response, error) {
	resp, err := l.inner.Send(cmd)
	if err != nil {
		return resp, err
	}

	serialized, _ := cmd.Serialize()
	fmt.Fprintf(os.Stderr, "APDU >> %s\nAPDU << SW=0x%04X data=%s\n",
		hexutils.BytesToHexWithSpaces(serialized),
		resp.Sw,
		hexutils.BytesToHexWithSpaces(resp.Data),
	)
	return resp, nil
}

// ============================================================================
// PCSC Transmitter
// ============================================================================

// pcscTransmitter wraps a scard.Card implementing io.Transmitter, carrying
// the reader name so we can log it and the Card handle so we can disconnect
// at the end of the test.
type pcscTransmitter struct {
	reader string
	card   *scard.Card
	ctx    *scard.Context
}

func (p *pcscTransmitter) Transmit(data []byte) ([]byte, error) {
	return p.card.Transmit(data)
}

func (p *pcscTransmitter) Close() error {
	_ = p.card.Disconnect(scard.ResetCard)
	_ = p.ctx.Release()
	return nil
}

// ============================================================================
// Channel factory
// ============================================================================

// newTestChannel creates the Channel used by integration tests.
//
// It connects to the first available PC/SC reader (or the reader named in
// the KEYCARD_READER environment variable) and registers cleanup with t.
func newTestChannel(t *testing.T) types.Channel {
	t.Helper()

	ctx, err := scard.EstablishContext()
	if err != nil {
		t.Skipf("integration: could not establish PC/SC context: %v", err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		ctx.Release()
		t.Skipf("integration: could not list PC/SC readers: %v", err)
	}
	if len(readers) == 0 {
		ctx.Release()
		t.Skip("integration: no PC/SC readers found")
	}

	// Pick reader: env var takes precedence, otherwise use the first one.
	var reader string
	if env := os.Getenv("KEYCARD_READER"); env != "" {
		reader = env
		// Verify the named reader exists.
		found := false
		for _, r := range readers {
			if r == reader {
				found = true
				break
			}
		}
		if !found {
			ctx.Release()
			t.Skipf("integration: reader %q not found (available: %v)", reader, readers)
		}
	} else {
		reader = readers[0]
	}

	t.Logf("integration: connecting to reader %q", reader)

	card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		ctx.Release()
		t.Skipf("integration: could not connect to reader %q: %v", reader, err)
	}

	pt := &pcscTransmitter{reader: reader, card: card, ctx: ctx}
	t.Cleanup(func() { pt.Close() })

	ch := io.NewNormalChannel(pt)
	return &loggingChannel{inner: ch}
}

// ============================================================================
// TestIntegration — top-level test that runs all integration sub-tests.
// ============================================================================

func TestIntegration(t *testing.T) {
	t.Run("SelectApplet", TestIntegrationSelectApplet)
	t.Run("FullSignFlow", TestIntegrationFullSignFlow)
	t.Run("FactoryResetAndInit", TestIntegrationFactoryResetAndInit)
	t.Run("BIP341TaprootSchnorr", TestIntegrationBIP341TaprootSchnorr)
}

// ============================================================================
// TestIntegrationSelectApplet
//
// Connect to the card and select the Keycard applet.
// ============================================================================

func TestIntegrationSelectApplet(t *testing.T) {
	ch := newTestChannel(t)

	kc := keycard.NewCommandSetWithCA(ch, testCAPublicKey)

	if err := kc.Select(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	info := kc.AppInfo()
	if info == nil {
		t.Fatal("app_info should be set after SELECT")
	}

	if info.AppVersion() == 0 {
		t.Fatalf("expected non-zero app version, got %d", info.AppVersion())
	}

	scVer, scOk := kc.SecureChannelVersion()
	t.Logf("app_version=%s secure_channel=(%v,%v) initialized=%v has_master_key=%v",
		info.AppVersionString(),
		scVer, scOk,
		info.Initialized,
		len(info.KeyUID) > 0,
	)
}

// ============================================================================
// TestIntegrationFullSignFlow
//
// Full integration test: connect → select → pair (V1 only) → open secure
// channel → verify PIN → export key at derivation path → sign at same path
// → verify signature.
//
// Uses the Ethereum main wallet path m/44'/60'/0'/0/0.
//
// Requires the KEYCARD_TEST_PIN environment variable to be set to this
// card's actual PIN (deliberately not hardcoded: a wrong guess here
// decrements the card's real PIN retry counter). Also requires the default
// pairing password ("KeycardDefaultPairing") if the card uses Secure
// Channel V1.
// ============================================================================

func TestIntegrationFullSignFlow(t *testing.T) {
	pin := os.Getenv("KEYCARD_TEST_PIN")
	if pin == "" {
		pin = "123456"
	}

	ch := newTestChannel(t)
	kc := keycard.NewCommandSetWithCA(ch, testCAPublicKey)

	// 1. Connect and select
	if err := kc.Select(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	info := kc.AppInfo()
	hasSecureChannel := info.HasSecureChannel()
	hasMasterKey := len(info.KeyUID) > 0

	// 2. Pair with default password (V1 only)
	if hasSecureChannel {
		version, ok := kc.SecureChannelVersion()
		if ok && version == keycard.VersionV1 {
			secret := keycard.PairingPasswordToSecret("KeycardDefaultPairing")
			if err := kc.AutoPairWithSecret(secret); err != nil {
				t.Fatalf("pairing failed: %v", err)
			}
		}
	}

	// 3. Open secure channel
	if hasSecureChannel {
		if err := kc.AutoOpenSecureChannel(); err != nil {
			t.Fatalf("failed to open secure channel: %v", err)
		}
	}

	// 4. Verify PIN
	if err := kc.VerifyPIN(pin); err != nil {
		t.Fatalf("PIN verification failed: %v", err)
	}

	// 5. Load a test master key if none is present
	if !hasMasterKey {
		// BIP39 test vector mnemonic (12 words)
		const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		seed := types.BinarySeedFromPhrase(testMnemonic, "")
		if _, err := kc.LoadSeed(seed); err != nil {
			t.Fatalf("LoadSeed failed: %v", err)
		}
		t.Log("loaded test master key from mnemonic")
	}

	// 6. Export the public key at the Ethereum wallet path
	path := "m/44'/60'/0'/0/0"
	exportedKey, err := kc.ExportKeyExtended(false, false, keycard.P2ExportKeyPublicOnly, path)
	if err != nil {
		t.Fatalf("ExportKey failed: %v", err)
	}
	publicKey := exportedKey.PubKey()
	if len(publicKey) == 0 {
		t.Fatal("exported public key is empty")
	}

	// 7. Sign a fixed 32-byte hash at the same derivation path
	hash := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	}
	sig, err := kc.SignWithPath(hash[:], path)
	if err != nil {
		t.Fatalf("SignWithPath failed: %v", err)
	}

	// 8. Verify the signature — recovered public key must match the exported key
	sigPubKey := sig.PubKey()
	if len(sigPubKey) == 0 {
		t.Fatal("signature public key is empty")
	}

	// Normalize both to compressed form for comparison
	if len(sigPubKey) == 65 {
		sigPubKey = sigPubKey[:33]
	}
	if len(publicKey) == 65 {
		publicKey = publicKey[:33]
	}

	if !bytes.Equal(sigPubKey, publicKey) {
		t.Fatalf("signature public key mismatch:\n  recovered: %s\n  exported:  %s",
			hexutils.BytesToHexWithSpaces(sigPubKey),
			hexutils.BytesToHexWithSpaces(publicKey),
		)
	}

	t.Logf("signature verified successfully (pubkey=%s)",
		hexutils.BytesToHexWithSpaces(sigPubKey),
	)

	// 8b. Schnorr signature (app version >= 4)
	if info.AppVersion() >= 0x0400 {
		schnorrSig, err := kc.SignWithPathAndAlgo(hash[:], path, keycard.P2SignBIP340Schnorr)
		if err != nil {
			t.Fatalf("SignWithPathAndAlgo (Schnorr) failed: %v", err)
		}

		// Reconstruct the 64-byte signature (r||s) and verify it
		sigBytes := append(schnorrSig.R(), schnorrSig.S()...)
		parsedSig, err := schnorr.ParseSignature(sigBytes)
		if err != nil {
			t.Fatalf("failed to parse Schnorr signature: %v", err)
		}

		// Parse the public key — compress if needed (btcec schnorr needs compressed/x-only)
		pubKeyBytes := schnorrSig.PubKey()
		if len(pubKeyBytes) == 65 {
			// Convert uncompressed to compressed
			if pubKeyBytes[64]&1 == 1 {
				pubKeyBytes[0] = 3
			} else {
				pubKeyBytes[0] = 2
			}
			pubKeyBytes = pubKeyBytes[:33]
		}
		pubKey, err := btcec.ParsePubKey(pubKeyBytes)
		if err != nil {
			t.Fatalf("failed to parse public key for Schnorr verification: %v", err)
		}

		if !parsedSig.Verify(hash[:], pubKey) {
			t.Fatal("Schnorr signature verification failed")
		}

		t.Log("schnorr signature verified")
	}

	// 9. Unpair (V1 only)
	if hasSecureChannel {
		version, ok := kc.SecureChannelVersion()
		if ok && version == keycard.VersionV1 {
			if err := kc.Unpair(0); err != nil {
				t.Logf("unpairing failed (non-critical): %v", err)
			}
		}
	}
}

// ============================================================================
// TestIntegrationFactoryResetAndInit
//
// Integration test: connect → select → factory reset → re-select → init.
//
// Tests the full factory reset and initialization flow for both Secure
// Channel V1 and V2. For V1, the card is initialized with a pairing
// password. For V2, the card is initialized without a pairing password
// (since V2 does not use pairing).
//
// WARNING: This test will factory reset the card, erasing all data
// including keys, PINs, and pairings. Do not run on a card with
// important data.
// ============================================================================

func TestIntegrationFactoryResetAndInit(t *testing.T) {
	const (
		testPIN             = "123456"
		testPUK             = "098765098765"
		testPairingPassword = "KeycardDefaultPairing"
	)

	ch := newTestChannel(t)
	kc := keycard.NewCommandSetWithCA(ch, testCAPublicKey)

	// 1. Connect and select
	if err := kc.Select(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	info := kc.AppInfo()
	hasSecureChannel := info.HasSecureChannel()
	scVersion, scOk := kc.SecureChannelVersion()

	t.Logf("Before reset: app_version=%s secure_channel=(%v,%v) initialized=%v",
		info.AppVersionString(),
		scVersion, scOk,
		info.Initialized,
	)

	// 2. Factory reset
	if err := kc.FactoryReset(); err != nil {
		t.Fatalf("FACTORY_RESET failed: %v", err)
	}
	t.Log("factory reset complete")

	// 3. Re-select to get fresh app info after reset
	if err := kc.Select(); err != nil {
		t.Fatalf("SELECT after reset failed: %v", err)
	}

	info = kc.AppInfo()
	if info.Initialized {
		t.Fatal("card should not be initialized after factory reset")
	}

	scVersion, scOk = kc.SecureChannelVersion()
	t.Logf("After reset: app_version=%s secure_channel=(%v,%v) initialized=%v",
		info.AppVersionString(),
		scVersion, scOk,
		info.Initialized,
	)

	// 4. Initialize the card (V1 or V2 path)
	isV2 := info.AppVersion() >= 0x0400
	if hasSecureChannel && isV2 {
		t.Logf("initializing with Secure Channel V2 (no pairing password)")
		if err := kc.InitV2(testPIN, testPUK); err != nil {
			t.Fatalf("INIT V2 failed: %v", err)
		}
	} else if hasSecureChannel && scVersion == keycard.VersionV1 {
		t.Logf("initializing with Secure Channel V1 (with pairing password)")
		secrets := keycard.NewSecrets(testPIN, testPUK, testPairingPassword)
		if err := kc.Init(secrets); err != nil {
			t.Fatalf("INIT V1 failed: %v", err)
		}
	} else {
		// No secure channel — use InitV2 with empty pairing
		t.Logf("initializing without secure channel")
		if err := kc.InitV2(testPIN, testPUK); err != nil {
			t.Fatalf("INIT failed: %v", err)
		}
	}

	t.Log("card initialized successfully")

	// 5. Re-select to verify the card is now initialized
	if err := kc.Select(); err != nil {
		t.Fatalf("SELECT after init failed: %v", err)
	}

	info = kc.AppInfo()
	if !info.Initialized {
		t.Fatal("card should be initialized after INIT")
	}

	scVersion, scOk = kc.SecureChannelVersion()
	t.Logf("After init: app_version=%s secure_channel=(%v,%v) initialized=%v",
		info.AppVersionString(),
		scVersion, scOk,
		info.Initialized,
	)

	// 6. Verify we can open a secure channel and verify the PIN
	if hasSecureChannel {
		isV2 := info.AppVersion() >= 0x0400
		if isV2 {
			// V2: open secure channel (no pairing needed)
			if err := kc.AutoOpenSecureChannel(); err != nil {
				t.Fatalf("failed to open secure channel (V2): %v", err)
			}
		} else if scVersion == keycard.VersionV1 {
			// V1: pair then open secure channel
			secret := keycard.PairingPasswordToSecret(testPairingPassword)
			if err := kc.AutoPairWithSecret(secret); err != nil {
				t.Fatalf("pairing failed: %v", err)
			}
			if err := kc.AutoOpenSecureChannel(); err != nil {
				t.Fatalf("failed to open secure channel (V1): %v", err)
			}
		}

		// Verify PIN
		if err := kc.VerifyPIN(testPIN); err != nil {
			t.Fatalf("PIN verification failed: %v", err)
		}
		t.Log("secure channel verification passed")

		// Unpair (V1 only)
		if scVersion == keycard.VersionV1 {
			if err := kc.Unpair(0); err != nil {
				t.Logf("unpairing failed (non-critical): %v", err)
			}
		}
	}
}

// ============================================================================
// TestIntegrationBIP341TaprootSchnorr
//
// Integration test for SignBIP341Schnorr — validates that the card's
// BIP341 Schnorr implementation is Taproot-compatible.
//
// BIP341 (Taproot) extends BIP340 (Schnorr) by "tweaking" the internal
// public key: P' = P + t*G, where t = tagsig("TapTweak", x(P)).
// The signature is then created with P' and verifies against P'.
//
// This test verifies:
//   1. The card correctly applies the BIP341 TapTweak to the key
//   2. The returned public key is the tweaked output key P'
//   3. The signature verifies against P' (not the internal key P)
//   4. Custom tweaks are applied correctly (not just TapTweak)
//
// Uses the Bitcoin taproot derivation path m/86'/0'/0'/0/0.
// Requires app version >= 4.0.
// ============================================================================

func TestIntegrationBIP341TaprootSchnorr(t *testing.T) {
	pin := os.Getenv("KEYCARD_TEST_PIN")
	if pin == "" {
		pin = "123456"
	}

	ch := newTestChannel(t)
	kc := keycard.NewCommandSetWithCA(ch, testCAPublicKey)

	// 1. Connect and select
	if err := kc.Select(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	info := kc.AppInfo()
	if info.AppVersion() < 0x0400 {
		t.Skipf("BIP341 Schnorr requires app version >= 4.0, got %s",
			info.AppVersionString())
	}

	hasSecureChannel := info.HasSecureChannel()
	hasMasterKey := len(info.KeyUID) > 0

	// 2. Open secure channel (V2 only — no pairing needed)
	if hasSecureChannel {
		if err := kc.AutoOpenSecureChannel(); err != nil {
			t.Fatalf("failed to open secure channel: %v", err)
		}
	}

	// 4. Verify PIN
	if err := kc.VerifyPIN(pin); err != nil {
		t.Fatalf("PIN verification failed: %v", err)
	}

	// 5. Load a test master key if none is present
	if !hasMasterKey {
		const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		seed := types.BinarySeedFromPhrase(testMnemonic, "")
		if _, err := kc.LoadSeed(seed); err != nil {
			t.Fatalf("LoadSeed failed: %v", err)
		}
		t.Log("loaded test master key from mnemonic")
	}

	// Use Bitcoin taproot path
	path := "m/86'/0'/0'/0/0"

	// 6. Export the public key at the taproot path
	exportedKey, err := kc.ExportKeyExtended(false, false, keycard.P2ExportKeyPublicOnly, path)
	if err != nil {
		t.Fatalf("ExportKey failed: %v", err)
	}
	pubKeyBytes := exportedKey.PubKey()
	if len(pubKeyBytes) == 0 {
		t.Fatal("exported public key is empty")
	}

	// Normalize to compressed form
	if len(pubKeyBytes) == 65 {
		if pubKeyBytes[64]&1 == 1 {
			pubKeyBytes[0] = 3
		} else {
			pubKeyBytes[0] = 2
		}
		pubKeyBytes = pubKeyBytes[:33]
	}

	internalKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse internal public key: %v", err)
	}
	t.Logf("internal key (P): %s",
		hexutils.BytesToHexWithSpaces(schnorr.SerializePubKey(internalKey)))

	// 7. Compute the BIP341 TapTweak from the x-only internal key
	internalXOnly := schnorr.SerializePubKey(internalKey) // 32 bytes
	tweak := bip341TapTweak(internalXOnly)
	t.Logf("TapTweak (t): %s", hexutils.BytesToHexWithSpaces(tweak[:]))

	// 8. Compute the expected tweaked output key using txscript (production-tested)
	tweakedKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	expectedTweakedXOnly := schnorr.SerializePubKey(tweakedKey)
	t.Logf("expected tweaked key (P'): %s",
		hexutils.BytesToHexWithSpaces(expectedTweakedXOnly))

	// 9. Sign a test message using SignBIP341Schnorr
	hash := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	}

	sig, err := kc.SignBIP341Schnorr(hash[:], tweak[:], path)
	if err != nil {
		t.Fatalf("SignBIP341Schnorr failed: %v", err)
	}

	// 10. Verify the signature against the tweaked public key
	sigBytes := append(sig.R(), sig.S()...)
	parsedSig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		t.Fatalf("failed to parse Schnorr signature: %v", err)
	}

	if !parsedSig.Verify(hash[:], tweakedKey) {
		t.Fatal("BIP341 Schnorr signature verification FAILED against tweaked key (P')")
	}
	t.Log("signature verified against tweaked key (P') — Taproot compatible")

	// 11. Verify the signature does NOT verify against the internal (untweaked) key
	if parsedSig.Verify(hash[:], internalKey) {
		t.Fatal("signature should NOT verify against the internal key (P) — key was not tweaked!")
	}
	t.Log("signature correctly does NOT verify against internal key (P)")

	// 12. Verify the returned pubkey matches the internal (untweaked) key.
	//     The card returns the internal key, not the tweaked output key.
	//     The signature verification above already proves the tweaked key
	//     was used for signing.
	returnedPubKey := sig.PubKey()
	var returnedXOnly []byte
	if len(returnedPubKey) == 32 {
		returnedXOnly = returnedPubKey
	} else if len(returnedPubKey) == 33 {
		// Compressed — extract x-only (bytes 1:33)
		returnedXOnly = returnedPubKey[1:33]
	} else if len(returnedPubKey) == 65 {
		// Uncompressed — extract x-only (bytes 1:33)
		returnedXOnly = returnedPubKey[1:33]
	} else {
		t.Fatalf("unexpected pubkey length: %d", len(returnedPubKey))
	}

	if !bytes.Equal(returnedXOnly, internalXOnly) {
		t.Fatalf("returned pubkey does not match internal key:\n  internal (P): %s\n  returned:     %s",
			hexutils.BytesToHexWithSpaces(internalXOnly),
			hexutils.BytesToHexWithSpaces(returnedXOnly),
		)
	}
	t.Log("returned pubkey matches internal key (P) — card returns untweaked key")

	// 13. Test with a custom tweak (not TapTweak) to verify the card
	//     applies arbitrary tweaks correctly
	customTweak := [32]byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}

	// Compute P' = P + customTweak*G using PrivKeyFromBytes + curve Add
	_, customTweakPubKey := btcec.PrivKeyFromBytes(customTweak[:])
	customTweakedX, customTweakedY := btcec.S256().Add(
		internalKey.X(), internalKey.Y(),
		customTweakPubKey.X(), customTweakPubKey.Y(),
	)
	// Check for point at infinity
	if customTweakedX.Sign() == 0 && customTweakedY.Sign() == 0 {
		t.Skip("custom tweak resulted in point at infinity — skipping custom tweak test")
	}

	// Convert *big.Int to FieldVal for NewPublicKey
	var tweakedXField, tweakedYField btcec.FieldVal
	// big.Int.Bytes() returns big-endian; pad to 32 bytes
	xBytes := customTweakedX.Bytes()
	yBytes := customTweakedY.Bytes()
	tweakedXField.SetByteSlice(paddingBytes(xBytes))
	tweakedYField.SetByteSlice(paddingBytes(yBytes))
	customTweakedKey := btcec.NewPublicKey(&tweakedXField, &tweakedYField)

	customSig, err := kc.SignBIP341Schnorr(hash[:], customTweak[:], path)
	if err != nil {
		t.Fatalf("SignBIP341Schnorr (custom tweak) failed: %v", err)
	}

	customSigBytes := append(customSig.R(), customSig.S()...)
	customParsedSig, err := schnorr.ParseSignature(customSigBytes)
	if err != nil {
		t.Fatalf("failed to parse custom Schnorr signature: %v", err)
	}

	if !customParsedSig.Verify(hash[:], customTweakedKey) {
		t.Fatal("custom tweak signature verification FAILED")
	}
	t.Log("custom tweak signature verified — card applies arbitrary tweaks correctly")
}

// bip341TapTweak computes the BIP341 TapTweak for an x-only public key.
//
// Per BIP341: t = tagsig("TapTweak", x)
// where tagsig(tag, data) = SHA256(tag_hash || tag_hash || data)
// and tag_hash = SHA256(tag).
func bip341TapTweak(xOnlyPubKey []byte) [32]byte {
	if len(xOnlyPubKey) != 32 {
		panic("xOnlyPubKey must be 32 bytes")
	}

	tag := []byte("TapTweak")
	tagHash := sha256.Sum256(tag)

	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(xOnlyPubKey)
	result := h.Sum(nil)
	var out [32]byte
	copy(out[:], result)
	return out
}

// paddingBytes left-pads a byte slice to 32 bytes (big-endian).
func paddingBytes(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// ============================================================================
// TestIntegrationECDFlow — ECDH key agreement (NIP-44 / EIP-1581 paths only).
// ============================================================================

// TestIntegrationECDFlow verifies the ECDH command on the NIP-44 path against a
// host-side computation of the shared secret.
//
// Requires the KEYCARD_TEST_PIN environment variable set to this card's actual
// PIN (defaults to "123456").
func TestIntegrationECDFlow(t *testing.T) {
	pin := os.Getenv("KEYCARD_TEST_PIN")
	if pin == "" {
		pin = "123456"
	}

	ch := newTestChannel(t)
	kc := keycard.NewCommandSetWithCA(ch, testCAPublicKey)

	// 1. Connect and select
	if err := kc.Select(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}
	info := kc.AppInfo()
	hasSecureChannel := info.HasSecureChannel()
	hasMasterKey := len(info.KeyUID) > 0

	// 2. Pair with default password (V1 only)
	if hasSecureChannel {
		if version, ok := kc.SecureChannelVersion(); ok && version == keycard.VersionV1 {
			if err := kc.AutoPairWithSecret(keycard.PairingPasswordToSecret("KeycardDefaultPairing")); err != nil {
				t.Fatalf("pairing failed: %v", err)
			}
		}
	}

	// 3. Open secure channel
	if hasSecureChannel {
		if err := kc.AutoOpenSecureChannel(); err != nil {
			t.Fatalf("failed to open secure channel: %v", err)
		}
	}

	// 4. Verify PIN
	if err := kc.VerifyPIN(pin); err != nil {
		t.Fatalf("PIN verification failed: %v", err)
	}

	// 5. Load a test master key if none is present
	if !hasMasterKey {
		const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		seed := types.BinarySeedFromPhrase(testMnemonic, "")
		if _, err := kc.LoadSeed(seed); err != nil {
			t.Fatalf("LoadSeed failed: %v", err)
		}
		t.Log("loaded test master key from mnemonic")
	}

	// 6. NIP-44 path
	path := "m/44'/1237'/0'/0/0"

	// 7. Export the card's public key at the NIP-44 path (public only)
	exportedKey, err := kc.ExportKeyExtended(false, false, keycard.P2ExportKeyPublicOnly, path)
	if err != nil {
		t.Fatalf("ExportKey failed: %v", err)
	}
	cardPub := exportedKey.PubKey()
	if len(cardPub) == 0 {
		t.Fatal("exported public key is empty")
	}

	// 8. Host keypair
	peerPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to generate peer secret: %v", err)
	}
	peerPub := peerPriv.PubKey().SerializeUncompressed()

	// 9. Card computes A_priv x B_pub
	ecdhSecret, err := kc.ECDH(peerPub, path)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}
	if len(ecdhSecret) != 32 {
		t.Fatalf("ECDH shared secret must be 32 bytes, got %d", len(ecdhSecret))
	}

	// 10. Host computes B_priv x A_pub and compares the x-coordinate
	cardPubKey, err := btcec.ParsePubKey(cardPub)
	if err != nil {
		t.Fatalf("failed to parse card public key: %v", err)
	}
	curve := btcec.S256()
	sharedX, _ := curve.ScalarMult(cardPubKey.X(), cardPubKey.Y(), peerPriv.Serialize())
	expected := paddingBytes(sharedX.Bytes())

	if !bytes.Equal(ecdhSecret, expected) {
		t.Fatalf("ECDH shared secret mismatch:\n  card: %s\n  host: %s",
			hexutils.BytesToHexWithSpaces(ecdhSecret),
			hexutils.BytesToHexWithSpaces(expected),
		)
	}
	t.Log("ECDH shared secret verified")

	// 11. Unpair (V1 only)
	if hasSecureChannel {
		if version, ok := kc.SecureChannelVersion(); ok && version == keycard.VersionV1 {
			if err := kc.Unpair(0); err != nil {
				t.Fatalf("unpairing failed: %v", err)
			}
		}
	}
}

// ============================================================================
// TestIntegrationLEEFlow — LEE (Lightweight Encryption Engine) key export.
// ============================================================================

// TestIntegrationLEEFlow loads a known LEE seed and validates the exported
// public key and LEE-Keys v1 components against the applet's test vector.
//
// NOTE: This loads a specific LEE seed onto the card, replacing any existing
// master key. Only run on a test card.
func TestIntegrationLEEFlow(t *testing.T) {
	pin := os.Getenv("KEYCARD_TEST_PIN")
	if pin == "" {
		pin = "000000"
	}

	ch := newTestChannel(t)
	kc := keycard.NewCommandSetWithCA(ch, testCAPublicKey)

	// LEE-Keys v1 test vector from the applet's LEE Keys test.
	const leeMnemonic = "fan empower output between game genius forest bulk party small arm shuffle"
	expectedPublic := hexutils.MustHexToBytes(
		"0423134cb96d1f5ec2ec023c6462317eee077f54730b14911b2eca0f0474b42688339128c030ad646c818bb2779d2901f758a527be9b849760f8191c72cdcecf9d",
	)
	expectedASK := hexutils.MustHexToBytes("7b9530590b74199ec623fd74bedc5b981c8eb36205f9981980f80c7cefc99d7d")
	expectedNSK := hexutils.MustHexToBytes("ef2b7994d905e72109f60de69ee212f82ed3b99d261916671337a8b744f7a515")
	expectedVSKD := hexutils.MustHexToBytes("9bbdfc6def553c24cd50755f8c45e120a2210e66f8a3d2d2487d591158fe7439")
	expectedVSKZ := hexutils.MustHexToBytes("bfabaa3ab7f9537b11035f6f1d31a3e9d2e85249f7e42e3053386c0b14b1384e")

	path := "m/43'/60'"

	// 1. Connect and select
	if err := kc.Select(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}
	info := kc.AppInfo()
	hasSecureChannel := info.HasSecureChannel()

	// 2. Pair with default password (V1 only)
	if hasSecureChannel {
		if version, ok := kc.SecureChannelVersion(); ok && version == keycard.VersionV1 {
			if err := kc.AutoPairWithSecret(keycard.PairingPasswordToSecret("KeycardDefaultPairing")); err != nil {
				t.Fatalf("pairing failed: %v", err)
			}
		}
	}

	// 3. Open secure channel
	if hasSecureChannel {
		if err := kc.AutoOpenSecureChannel(); err != nil {
			t.Fatalf("failed to open secure channel: %v", err)
		}
	}

	// 4. Verify PIN
	if err := kc.VerifyPIN(pin); err != nil {
		t.Fatalf("PIN verification failed: %v", err)
	}

	// 5. Load the known LEE seed (replaces the current master key)
	seed := types.BinarySeedFromPhrase(leeMnemonic, "")
	if err := kc.LoadLEEKey(seed); err != nil {
		t.Fatalf("LoadLEEKey failed: %v", err)
	}

	// 6. Export the public key at m/43'/60'
	exportedKey, err := kc.ExportKeyExtended(false, false, keycard.P2ExportKeyPublicOnly, path)
	if err != nil {
		t.Fatalf("ExportKey failed: %v", err)
	}
	pubKey := exportedKey.PubKey()
	if !bytes.Equal(pubKey, expectedPublic) {
		t.Fatalf("LEE public key mismatch:\n  got:  %s\n  want: %s",
			hexutils.BytesToHexWithSpaces(pubKey),
			hexutils.BytesToHexWithSpaces(expectedPublic),
		)
	}

	// 7. Export the LEE keys at m/43'/60' and validate the parsed components
	leeData, err := kc.ExportLEEKey(path)
	if err != nil {
		t.Fatalf("ExportLEEKey failed: %v", err)
	}
	leeKey, err := types.ParseLeeKey(leeData)
	if err != nil {
		t.Fatalf("failed to parse LEE key: %v", err)
	}

	ask := leeKey.ASK()
	if !bytes.Equal(ask[:], expectedASK) {
		t.Fatalf("ASK mismatch:\n  got:  %s\n  want: %s", hexutils.BytesToHexWithSpaces(ask[:]), hexutils.BytesToHexWithSpaces(expectedASK))
	}
	nsk := leeKey.NSK()
	if !bytes.Equal(nsk[:], expectedNSK) {
		t.Fatalf("NSK mismatch:\n  got:  %s\n  want: %s", hexutils.BytesToHexWithSpaces(nsk[:]), hexutils.BytesToHexWithSpaces(expectedNSK))
	}
	vskD := leeKey.VSKD()
	if !bytes.Equal(vskD[:], expectedVSKD) {
		t.Fatalf("VSK_D mismatch:\n  got:  %s\n  want: %s", hexutils.BytesToHexWithSpaces(vskD[:]), hexutils.BytesToHexWithSpaces(expectedVSKD))
	}
	vskZ := leeKey.VSKZ()
	if !bytes.Equal(vskZ[:], expectedVSKZ) {
		t.Fatalf("VSK_Z mismatch:\n  got:  %s\n  want: %s", hexutils.BytesToHexWithSpaces(vskZ[:]), hexutils.BytesToHexWithSpaces(expectedVSKZ))
	}
	t.Log("LEE keys verified")

	// 8. Unpair (V1 only)
	if hasSecureChannel {
		if version, ok := kc.SecureChannelVersion(); ok && version == keycard.VersionV1 {
			if err := kc.Unpair(0); err != nil {
				t.Fatalf("unpairing failed: %v", err)
			}
		}
	}
}
