package globalplatform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeySetValidate(t *testing.T) {
	tests := []struct {
		name    string
		keySet  KeySet
		wantErr bool
	}{
		{"scp02 16 bytes", NewSCP02KeySet(make([]byte, 16)), false},
		{"scp02 24 bytes", NewSCP02KeySet(make([]byte, 24)), false},
		{"scp02 8 bytes", NewSCP02KeySet(make([]byte, 8)), true},
		{"scp02 split keys", NewSCP02KeySetSplit(make([]byte, 16), make([]byte, 24)), false},
		{"scp02 empty mac", NewSCP02KeySetSplit(make([]byte, 16), nil), true},
		{"scp03 aes128", NewSCP03KeySet(1, make([]byte, 16), make([]byte, 16), make([]byte, 16)), false},
		{"scp03 aes256 without dek", NewSCP03KeySet(1, make([]byte, 32), make([]byte, 32), nil), false},
		{"scp03 short mac", NewSCP03KeySet(1, make([]byte, 16), make([]byte, 8), nil), true},
		{"scp03 mixed lengths", NewSCP03KeySet(1, make([]byte, 16), make([]byte, 32), nil), true},
		{"scp03 short dek", NewSCP03KeySet(1, make([]byte, 16), make([]byte, 16), make([]byte, 8)), true},
		{"no keys", KeySet{}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.keySet.Validate()
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// The defaults have to cover both protocols, since a caller cannot tell what a card holds.
func TestDefaultKeySets(t *testing.T) {
	var scp02, scp03 bool

	for _, keySet := range DefaultKeySets() {
		assert.NoError(t, keySet.Validate())

		switch keySet.Protocol() {
		case SCPVersion02:
			scp02 = true
		case SCPVersion03:
			scp03 = true
		}
	}

	assert.True(t, scp02, "no scp02 key set in the defaults")
	assert.True(t, scp03, "no scp03 key set in the defaults")
}
