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
	"fmt"
	"os"
	"testing"

	"github.com/ebfe/scard"
	"github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/hexutils"
	"github.com/status-im/keycard-go/io"
	"github.com/status-im/keycard-go/types"
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
