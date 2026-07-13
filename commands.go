package keycard

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/derivationpath"
	"github.com/status-im/keycard-go/globalplatform"
)

func NewCommandInit(data []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsInit,
		0,
		0,
		data,
	)
}

func NewCommandPairFirstStep(challenge []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsPair,
		P1PairingFirstStep,
		0,
		challenge,
	)
}

func NewCommandPairFinalStep(cryptogramHash []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsPair,
		P1PairingFinalStep,
		0,
		cryptogramHash,
	)
}

func NewCommandUnpair(index uint8) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsUnpair,
		index,
		0,
		[]byte{},
	)
}

func NewCommandIdentify(challenge []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsIdentify,
		0,
		0,
		challenge,
	)
}

func NewCommandOpenSecureChannel(pairingIndex uint8, pubKey []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsOpenSecureChannel,
		pairingIndex,
		0,
		pubKey,
	)
}

func NewCommandMutuallyAuthenticate(data []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsMutuallyAuthenticate,
		0,
		0,
		data,
	)
}

func NewCommandGetStatus(p1 uint8) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsGetStatus,
		p1,
		0,
		[]byte{},
	)
}

func NewCommandGenerateKey() *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsGenerateKey,
		0,
		0,
		[]byte{},
	)
}

func NewCommandGenerateMnemonic(checksumSize byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsGenerateMnemonic,
		checksumSize,
		0,
		[]byte{},
	)
}

func NewCommandRemoveKey() *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsRemoveKey,
		0,
		0,
		[]byte{},
	)
}

func NewCommandVerifyPIN(pin string) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsVerifyPIN,
		0,
		0,
		[]byte(pin),
	)
}

func NewCommandChangePIN(pin string) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsChangePIN,
		P1ChangePinPIN,
		0,
		[]byte(pin),
	)
}

func NewCommandUnblockPIN(puk string, newPIN string) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsUnblockPIN,
		0,
		0,
		[]byte(puk+newPIN),
	)
}

func NewCommandChangePUK(puk string) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsChangePIN,
		P1ChangePinPUK,
		0,
		[]byte(puk),
	)
}

func NewCommandChangePairingSecret(secret []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsChangePIN,
		P1ChangePinPairingSecret,
		0,
		secret,
	)
}

func NewCommandLoadSeed(seed []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsLoadKey,
		P1LoadKeySeed,
		0,
		seed,
	)
}

func NewCommandDeriveKey(pathStr string) (*apdu.Command, error) {
	startingPoint, path, err := derivationpath.Decode(pathStr)
	if err != nil {
		return nil, err
	}

	p1, err := derivationP1FromStartingPoint(startingPoint)
	if err != nil {
		return nil, err
	}

	data := new(bytes.Buffer)
	for _, segment := range path {
		if err := binary.Write(data, binary.BigEndian, segment); err != nil {
			return nil, err
		}
	}

	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsDeriveKey,
		p1,
		0,
		data.Bytes(),
	), nil
}

// Export a key
//
//	 @param {p1}
//			0x00: current key - returns the key that is currently loaded and ready for signing. Does not use derivation path
//			0x01: derive - returns derived key
//			0x02: derive and make current - returns derived key and also sets it to the current key
//	 @param {p2}
//			0x00: return public and private key pair
//			0x01: return only the public key
//			0x02: return extended public key
//	 @param {pathStr}
//			Derivation path of format "m/x/x/x/x/x", e.g. "m/44'/0'/0'/0/0"
func NewCommandExportKey(p1 uint8, p2 uint8, pathStr string) (*apdu.Command, error) {
	startingPoint, path, err := derivationpath.Decode(pathStr)
	if err != nil {
		return nil, err
	}

	deriveP1, err := derivationP1FromStartingPoint(startingPoint)
	if err != nil {
		return nil, err
	}

	data := new(bytes.Buffer)
	for _, segment := range path {
		if err := binary.Write(data, binary.BigEndian, segment); err != nil {
			return nil, err
		}
	}

	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsExportKey,
		p1|deriveP1,
		p2,
		data.Bytes(),
	), nil
}

func NewCommandSetPinlessPath(pathStr string) (*apdu.Command, error) {
	startingPoint, path, err := derivationpath.Decode(pathStr)
	if err != nil {
		return nil, err
	}

	if len(path) > 0 && startingPoint != derivationpath.StartingPointMaster {
		return nil, fmt.Errorf("pinless path must be set with an absolute path")
	}

	data := new(bytes.Buffer)
	for _, segment := range path {
		if err := binary.Write(data, binary.BigEndian, segment); err != nil {
			return nil, err
		}
	}

	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsSetPinlessPath,
		0,
		0,
		data.Bytes(),
	), nil
}

func NewCommandSign(data []byte, p1 uint8, pathStr string) (*apdu.Command, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("data length must be 32, got %d", len(data))
	}

	if p1 == P1SignDerive || p1 == P1SignDeriveAndMakeCurrent {
		_, path, err := derivationpath.Decode(pathStr)
		if err != nil {
			return nil, err
		}

		pathData := new(bytes.Buffer)
		for _, segment := range path {
			if err := binary.Write(pathData, binary.BigEndian, segment); err != nil {
				return nil, err
			}
		}

		data = append(data, pathData.Bytes()...)
	}

	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsSign,
		p1,
		1,
		data,
	), nil
}

func NewCommandGetData(typ uint8) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsGetData,
		typ,
		0,
		[]byte{},
	)
}

func NewCommandStoreData(typ uint8, data []byte) *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsStoreData,
		typ,
		0,
		data,
	)
}

func NewCommandFactoryReset() *apdu.Command {
	return apdu.NewCommand(
		globalplatform.ClaGp,
		InsFactoryReset,
		P1FactoryResetMagic,
		P2FactoryResetMagic,
		[]byte{},
	)
}

// Internal function. Get the type of starting point for the derivation path.
// Used for both DeriveKey and ExportKey
func derivationP1FromStartingPoint(s derivationpath.StartingPoint) (uint8, error) {
	switch s {
	case derivationpath.StartingPointMaster:
		return P1DeriveKeyFromMaster, nil
	case derivationpath.StartingPointParent:
		return P1DeriveKeyFromParent, nil
	case derivationpath.StartingPointCurrent:
		return P1DeriveKeyFromCurrent, nil
	default:
		return uint8(0), fmt.Errorf("invalid startingPoint %d", s)
	}
}
