# keycard-go

`keycard-go` is a set of Go packages for interacting with the [Status Keycard](https://github.com/keycard-tech/status-keycard), a secure NFC-based hardware wallet.

If you only need a CLI tool to initialize your card, check out [keycard-cli](https://github.com/keycard-tech/keycard-cli).

## Packages

| Package | Description |
|---|---|
| `keycard` | Main API — `CommandSet` for card operations, secure channel, pairing |
| `keycard/globalplatform` | GlobalPlatform commands — applet installation, SCP02 and SCP03 secure channel |
| `keycard/apdu` | APDU command/response types and encoding |
| `keycard/crypto` | Cryptographic utilities (ECDH, AES-CCM, HMAC, PBKDF2, zeroization) |
| `keycard/derivationpath` | BIP32 derivation path parsing and encoding |
| `keycard/identifiers` | AIDs and instance identifiers for Keycard, NDEF, Cash |
| `keycard/tlv` | TLV encoding/decoding |
| `keycard/types` | Shared types — `Pairing`, `Signature`, `Bip32KeyPair`, `ApplicationInfo`, etc. |

## Keycard Commands

### Setup and Status

| Command | Method(s) |
|---|---|
| SELECT | `Select()` |
| INIT | `Init()`, `InitWithSecret()`, `InitV2()`, `InitWithOptions()` |
| FACTORY RESET | `FactoryReset()` |
| GET STATUS | `GetStatus()`, `GetStatusApplication()`, `GetStatusKeyPath()` |
| IDENTIFY | `Identify()` |

### Secure Channel

| Feature | Details |
|---|---|
| **V1** (pairing-based) | `OpenSecureChannel()`, `AutoOpenSecureChannel()` |
| **V2** (certificate-based, app ≥ 4.0) | `AutoOpenSecureChannel()`, `AutoPair()` |
| Auto-detection | `SecureChannelVersion()` — selected automatically after `Select()` |
| Mutual Authentication | Performed automatically during channel open |

### Pairing (Secure Channel V1)

| Command | Method(s) |
|---|---|
| PAIR | `Pair()` (legacy), `AutoPairWithMode()`, `AutoPairWithSecret()`, `AutoPairWithSecretAndMode()` |
| UNPAIR | `Unpair(index)` |
| UNPAIR OTHERS | `UnpairOthers()` |
| CHANGE PAIRING PASSWORD | `ChangePairingPassword()` |
| Pairing modes | `P2PairAny`, `P2PairEphemeral`, `P2PairPersistent` |

### PIN / PUK Management

| Command | Method(s) |
|---|---|
| VERIFY PIN | `VerifyPIN()` |
| CHANGE PIN | `ChangePIN()` |
| UNBLOCK PIN | `UnblockPIN(puk, newPIN)` |
| CHANGE PUK | `ChangePUK()` |

### Key Management

| Command | Method(s) |
|---|---|
| LOAD KEY (BIP32) | `LoadKeyBIP32()`, `LoadKeyBIP32OmitPublic()` |
| LOAD KEY (Seed) | `LoadSeed()` |
| LOAD KEY (LEE) | `LoadLEEKey()` |
| DERIVE KEY | `DeriveKey(path)` |
| GENERATE KEY | `GenerateKey()` |
| GENERATE MNEMONIC | `GenerateMnemonic(checksumSize)` |
| REMOVE KEY | `RemoveKey()` |
| EXPORT KEY (BIP32) | `ExportKey()`, `ExportKeyExtended()`, `ExportKeyWithP2()`, `ExportCurrentKey()` |
| EXPORT KEY (LEE) | `ExportLEEKey(keypath)` |
| EXPORT KEY (BIP85) | `ExportBIP85(keypath, length)` |

### Signing

| Command | Method(s) | Algorithms |
|---|---|---|
| SIGN (current key) | `Sign(data)` | ECDSA, EdDSA/Ed25519, BLS12-381, BIP340 Schnorr |
| SIGN (derived path) | `SignWithPath(data, path)`, `SignWithPathAndAlgo(data, path, algo)` | Same |
| SIGN (pinless) | `SignPinless(data)` | ECDSA |
| SET PINLESS PATH | `SetPinlessPath(path)` | — |
| RESET PINLESS PATH | `ResetPinlessPath()` | — |

Sign algorithm constants: `P2SignECDSA`, `P2SignEdDSAEd25519`, `P2SignBLS12_381`, `P2SignBIP340Schnorr`.

### Data Storage

| Command | Method(s) |
|---|---|
| STORE DATA | `StoreData(typ, data)`, `StoreDataWithOffset(typ, data, offset)` |
| GET DATA | `GetData(typ)` |
| SET NDEF | `SetNDEF(ndef)` |
| GET CHALLENGE | `GetChallenge(length)` |

Data type constants: `P1StoreDataPublic`, `P1StoreDataNDEF`, `P1StoreDataCash`.

## GlobalPlatform (Applet Management)

| Command | Method(s) |
|---|---|
| SELECT | `globalplatform.NewCommandSelect(aid)` |
| INITIALIZE UPDATE | `globalplatform.NewCommandInitializeUpdate(challenge, keyVersion)` |
| EXTERNAL AUTHENTICATE | `globalplatform.NewCommandExternalAuthenticateSCP02(hostCryptogram)`, `globalplatform.NewCommandExternalAuthenticateSCP03(level, hostCryptogram)` |
| GET RESPONSE | `globalplatform.NewCommandGetResponse(length)` |
| DELETE | `globalplatform.NewCommandDelete(aid, p2)` |
| INSTALL FOR LOAD | `globalplatform.NewCommandInstallForLoad(aid, sdaid)` |
| INSTALL FOR INSTALL | `globalplatform.NewCommandInstallForInstall(pkgAID, appletAID, instanceAID, params)` |
| Secure messaging | `globalplatform.SCP02Wrapper`, `globalplatform.SCP03Wrapper`, `globalplatform.SecureChannel` |
| Applet Loading | `globalplatform.NewLoadCommandStream(file, blockSize)` |

### Secure Channel Session

```go
cmdSet := globalplatform.NewCommandSet(channel,
	globalplatform.WithKeySets(globalplatform.NewSCP03KeySet(0x01, enc, mac, dek)),
	globalplatform.WithSecurityLevel(globalplatform.LevelCDECMAC))

cmdSet.Select()
cmdSet.OpenSecureChannel()
cmdSet.LoadKeycardPackage(capFile, progress)
cmdSet.InstallKeycardApplet()
```

`OpenSecureChannel` sends an INITIALIZE UPDATE per key set, in order, and keeps the one
whose card cryptogram verifies; `DefaultKeySets()` holds the public development keys used
when no `WithKeySets` is given. The protocol is the one the card reports in its response,
so SCP02 and SCP03 cards need no configuration difference.

| Level | Commands | Responses |
|---|---|---|
| `LevelCMAC` (default) | MAC | — |
| `LevelCDECMAC` | encrypted + MAC | — |
| `LevelCMACRMAC` | MAC | MAC |
| `LevelCDECMACRMAC` | encrypted + MAC | MAC |
| `LevelFull` | encrypted + MAC | encrypted + MAC |

Levels with R-MAC need a card whose `i` parameter advertises it, and are rejected before
EXTERNAL AUTHENTICATE otherwise. `SecureChannel.MaxCommandData` gives the largest command
body the level leaves available, which is what `NewLoadCommandStream` sizes its blocks
with.

A card answering a response-protected command with `61xx` is continued by an
unauthenticated GET RESPONSE on the underlying channel, so R-MAC levels only work where
the card MACs the GET RESPONSE output as well.

## Cash Application

| Command | Method(s) |
|---|---|
| SELECT | `CashCommandSet.Select()` |
| SIGN | `CashCommandSet.Sign(data)` |

## Secure Channel Versions

| Version | App Version | Authentication | Notes |
|---|---|---|---|
| **V1** | < 4.0 | ECDH + pairing password (PBKDF2) | Up to 5 persistent pairing slots |
| **V2** | ≥ 4.0 | ECDH + X.509 certificate | CA-trusted, no pairing password needed |

V2 is auto-selected for app version ≥ 4.0. Use `AutoOpenSecureChannel()` and `AutoPairWithMode()` for version-agnostic code.
