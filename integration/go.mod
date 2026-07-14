module github.com/status-im/keycard-go/integration

go 1.17

require (
	github.com/ebfe/scard v0.0.0-20241214075232-7af069cabc25
	github.com/status-im/keycard-go v0.0.0
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/ethereum/go-ethereum v1.10.26 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	golang.org/x/crypto v0.1.0 // indirect
	golang.org/x/sys v0.2.0 // indirect
	golang.org/x/text v0.4.0 // indirect
)

replace github.com/status-im/keycard-go => ../
