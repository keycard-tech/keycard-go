package types

import (
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/keycard-tech/keycard-go/v4/tlv"
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
	r := tlv.NewBerTlvReader(data)

	tpl, err := r.ReadPrimitive(tlv.TLV_KEY_TEMPLATE)
	if err != nil {
		return nil, err
	}

	inner := tlv.NewBerTlvReader(tpl)

	pubKey, err := inner.ReadPrimitiveIfPresent(tlv.TLV_PUB_KEY)
	if err != nil {
		return nil, err
	}

	privKey, err := inner.ReadPrimitiveIfPresent(tlv.TLV_PRIV_KEY)
	if err != nil {
		return nil, err
	}

	chainCode, err := inner.ReadPrimitiveIfPresent(tlv.TLV_CHAIN_CODE)
	if err != nil {
		return nil, err
	}

	if len(pubKey) == 0 && len(privKey) > 0 {
		ecdsaKey, err := ethcrypto.HexToECDSA(fmt.Sprintf("%x", privKey))
		if err != nil {
			return nil, err
		}

		pubKey = ethcrypto.FromECDSAPub(&ecdsaKey.PublicKey)
	}

	return &ExportedKey{pubKey, privKey, chainCode}, nil
}
