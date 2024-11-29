package types

import (
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/keycard-go/apdu"
)

var (
	TagExportKeyTemplate    = apdu.Tag{0xA1}
	TagExportKeyPublic      = apdu.Tag{0x80}
	TagExportKeyPrivate     = apdu.Tag{0x81}
	TagExportKeyPublicChain = apdu.Tag{0x82}
)

type ExportedKey struct {
	pubKey    []byte
	privKey   []byte
	chainCode []byte
}

func (k *ExportedKey) PubKey() []byte {
	return k.pubKey
}

func (k *ExportedKey) PrivKey() []byte {
	return k.privKey
}

func (k *ExportedKey) ChainCode() []byte {
	return k.chainCode
}

func ParseExportKeyResponse(data []byte) (*ExportedKey, error) {
	tpl, err := apdu.FindTag(data, TagExportKeyTemplate)
	if err != nil {
		return nil, err
	}

	pubKey := tryFindTag(tpl, TagExportKeyPublic)
	privKey := tryFindTag(tpl, TagExportKeyPrivate)
	chainCode := tryFindTag(tpl, TagExportKeyPublicChain)

	if len(pubKey) == 0 && len(privKey) > 0 {
		ecdsaKey, err := ethcrypto.HexToECDSA(fmt.Sprintf("%x", privKey))
		if err != nil {
			return nil, err
		}

		pubKey = ethcrypto.FromECDSAPub(&ecdsaKey.PublicKey)
	}

	return &ExportedKey{pubKey, privKey, chainCode}, nil
}

func tryFindTag(tpl []byte, tags ...apdu.Tag) []byte {
	data, err := apdu.FindTag(tpl, tags...)
	if err != nil {
		return nil
	}

	return data
}
