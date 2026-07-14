package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMetadata(t *testing.T) {
	m, err := ParseMetadata([]byte{0x23, 0x31, 0x32, 0x33, 0x00, 0x00, 0x04, 0x03, 0x82, 0x7a, 0x28, 0x01})
	require.NoError(t, err)
	assert.Equal(t, "123", m.Name())
	assert.Equal(t, []uint64{0x00, 0x04, 0x05, 0x06, 0x07, 0x7a28, 0x7a29}, m.Wallets())
}

func TestSerialize(t *testing.T) {
	m, err := NewMetadata("123", []uint32{0x00, 0x04, 0x05, 0x06, 0x07, 0x7a28, 0x7a29})
	require.NoError(t, err)
	assert.Equal(t, []byte{0x23, 0x31, 0x32, 0x33, 0x00, 0x00, 0x04, 0x03, 0x82, 0x7a, 0x28, 0x01}, m.Serialize())
}

func TestMetadataRoundtrip(t *testing.T) {
	m := EmptyMetadata()
	m.SetName("TestCard")
	m.AddWallet(1)
	m.AddWallet(2)
	m.AddWallet(3)
	m.AddWallet(100)

	bytes := m.Serialize()
	parsed, err := ParseMetadata(bytes)
	require.NoError(t, err)

	assert.Equal(t, "TestCard", parsed.Name())
	assert.Equal(t, []uint64{1, 2, 3, 100}, parsed.Wallets())
}

func TestMetadataEmptyWallets(t *testing.T) {
	m := EmptyMetadata()
	m.SetName("EmptyCard")
	bytes := m.Serialize()
	parsed, err := ParseMetadata(bytes)
	require.NoError(t, err)
	assert.Equal(t, "EmptyCard", parsed.Name())
	assert.Empty(t, parsed.Wallets())
}

func TestMetadataInvalidVersion(t *testing.T) {
	_, err := ParseMetadata([]byte{0x00, 'T', 'e', 's', 't'})
	assert.Error(t, err)
}

func TestMetadataNameTooLong(t *testing.T) {
	m := EmptyMetadata()
	err := m.SetName("ThisNameIsWayTooLongForACard")
	assert.Error(t, err)
}

func TestMetadataWalletRangeCompression(t *testing.T) {
	m := EmptyMetadata()
	m.SetName("RangeCard")
	for i := uint64(1); i <= 5; i++ {
		m.AddWallet(i)
	}
	m.AddWallet(20)
	m.AddWallet(21)

	bytes := m.Serialize()
	parsed, err := ParseMetadata(bytes)
	require.NoError(t, err)
	assert.Equal(t, m.Wallets(), parsed.Wallets())
}

func TestMetadataHugeRangeCountRejected(t *testing.T) {
	// Header: version 1, empty name.
	data := []byte{0x20}
	// start = 0
	data = append(data, 0x00)
	// count = 0xFFFFFFFF (5-byte long form), which would otherwise
	// drive a ~4 billion iteration loop.
	data = append(data, 0x84, 0xFF, 0xFF, 0xFF, 0xFF)

	_, err := ParseMetadata(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestMetadataRejectsIndefiniteLengthPrefix(t *testing.T) {
	// A length-prefix byte of exactly 0x80 (indefinite length) must be rejected
	data := []byte{0x20, 0x80, 0x00}
	_, err := ParseMetadata(data)
	assert.Error(t, err)
}

func TestMetadataRejectsLengthPrefixOver4Bytes(t *testing.T) {
	// A long-form prefix claiming more than 4 length bytes (0x85 = 5)
	data := []byte{0x20, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := ParseMetadata(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

func TestMetadataRejectsAggregateCountOverMultipleRanges(t *testing.T) {
	// Two ranges, each individually under MAX_WALLET_RANGE_COUNT, but
	// together over MAX_TOTAL_WALLETS.
	data := []byte{0x20} // header, empty name
	for i := 0; i < 2; i++ {
		data = append(data, 0x00) // start = 0
		data = append(data, 0x82) // long form, 2 length bytes
		data = append(data, 0xC3, 0x50) // count = 50,000
	}

	_, err := ParseMetadata(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Total wallet count too large")
}

func TestMetadataAllowsMultipleRangesWithinAggregateCap(t *testing.T) {
	// Two small ranges that stay well within the aggregate cap
	data := []byte{0x20}
	data = append(data, 0x00) // start = 0
	data = append(data, 0x02) // count = 2 -> wallets 0,1,2
	data = append(data, 0x0A) // start = 10
	data = append(data, 0x01) // count = 1 -> wallets 10,11

	parsed, err := ParseMetadata(data)
	require.NoError(t, err)
	assert.Equal(t, 5, len(parsed.Wallets()))
}

func TestMetadataBackwardsCompatPaths(t *testing.T) {
	m := EmptyMetadata()
	m.SetName("Compat")
	m.AddPath(1)
	m.AddPath(2)

	paths := m.Paths()
	assert.Equal(t, []uint32{1, 2}, paths)
}

func TestMetadataBackwardsCompatRemovePath(t *testing.T) {
	m := EmptyMetadata()
	m.SetName("Compat")
	m.AddWallet(1)
	m.AddWallet(2)
	m.AddWallet(3)
	m.RemovePath(2)

	assert.Equal(t, []uint64{1, 3}, m.Wallets())
}

func TestMetadataWallets(t *testing.T) {
	m := EmptyMetadata()
	m.SetName("Test")
	m.AddWallet(10)
	m.AddWallet(5)
	m.AddWallet(20)

	wallets := m.Wallets()
	assert.Equal(t, []uint64{5, 10, 20}, wallets)
}

func TestMetadataRemoveWallet(t *testing.T) {
	m := EmptyMetadata()
	m.SetName("Test")
	m.AddWallet(1)
	m.AddWallet(2)
	m.AddWallet(3)
	m.RemoveWallet(2)

	assert.Equal(t, []uint64{1, 3}, m.Wallets())
}

func TestMetadataAddWalletNoDups(t *testing.T) {
	m := EmptyMetadata()
	m.AddWallet(1)
	m.AddWallet(1)
	m.AddWallet(2)

	assert.Equal(t, []uint64{1, 2}, m.Wallets())
}
