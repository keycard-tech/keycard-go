package types

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/keycard-tech/keycard-go/tlv"
)

const (
	// MaxWalletRangeCount is the upper bound on a single encoded wallet range's count.
	MaxWalletRangeCount = 100000
	// MaxTotalWallets is the upper bound on the total number of wallet IDs across all ranges.
	MaxTotalWallets = 100000
)

type Metadata struct {
	name    string
	wallets []uint64
}

func EmptyMetadata() *Metadata {
	return &Metadata{"", nil}
}

func NewMetadata(name string, paths []uint32) (*Metadata, error) {
	m := EmptyMetadata()

	if err := m.SetName(name); err != nil {
		return nil, err
	}

	for i := 0; i < len(paths); i++ {
		m.AddWallet(uint64(paths[i]))
	}

	return m, nil
}

func ParseMetadata(data []byte) (*Metadata, error) {
	if len(data) == 0 {
		return nil, errors.New("empty metadata data")
	}

	header := data[0]
	version := header >> 5

	if version != 1 {
		return nil, fmt.Errorf("invalid metadata version: %d", version)
	}

	nameLen := int(header & 0x1F)
	off := 1

	if off+nameLen > len(data) {
		return nil, errors.New("metadata data too short for card name")
	}

	cardName := string(data[off : off+nameLen])
	off += nameLen

	var wallets []uint64
	var totalInserted uint64

	for off < len(data) {
		start, nextOff, err := tlv.DecodeBerLength(data, off)
		if err != nil {
			return nil, err
		}
		off = nextOff

		count, nextOff, err := tlv.DecodeBerLength(data, off)
		if err != nil {
			return nil, err
		}
		off = nextOff

		if count > MaxWalletRangeCount {
			return nil, fmt.Errorf("wallet range count too large: %d (max %d)", count, MaxWalletRangeCount)
		}

		totalInserted += uint64(count) + 1
		if totalInserted > MaxTotalWallets {
			return nil, fmt.Errorf("Total wallet count too large: %d (max %d)", totalInserted, MaxTotalWallets)
		}

		for i := uint64(0); i <= uint64(count); i++ {
			wallets = append(wallets, uint64(start)+i)
		}
	}

	return &Metadata{cardName, wallets}, nil
}

func (m *Metadata) Name() string {
	return m.name
}

func (m *Metadata) SetName(name string) error {
	if len(name) > 20 {
		return errors.New("name longer than 20 chars")
	}

	m.name = name
	return nil
}

// Wallets returns the set of wallet IDs.
func (m *Metadata) Wallets() []uint64 {
	return m.wallets
}

// Paths returns the set of wallet IDs as uint32 for backwards compatibility.
// Deprecated: use Wallets() instead.
func (m *Metadata) Paths() []uint32 {
	paths := make([]uint32, len(m.wallets))
	for i, w := range m.wallets {
		paths[i] = uint32(w)
	}
	return paths
}

// AddWallet adds a wallet ID.
func (m *Metadata) AddWallet(id uint64) {
	// Insert in sorted order, no duplicates
	idx := sortInsertPos(m.wallets, id)
	if idx < len(m.wallets) && m.wallets[idx] == id {
		return // already present
	}
	m.wallets = append(m.wallets, 0)
	copy(m.wallets[idx+1:], m.wallets[idx:])
	m.wallets[idx] = id
}

// AddPath adds a wallet ID for backwards compatibility.
// Deprecated: use AddWallet() instead.
func (m *Metadata) AddPath(path uint32) {
	m.AddWallet(uint64(path))
}

// RemoveWallet removes a wallet ID.
func (m *Metadata) RemoveWallet(id uint64) {
	idx := sortSearchPos(m.wallets, id)
	if idx < len(m.wallets) && m.wallets[idx] == id {
		m.wallets = append(m.wallets[:idx], m.wallets[idx+1:]...)
	}
}

// RemovePath removes a wallet ID for backwards compatibility.
// Deprecated: use RemoveWallet() instead.
func (m *Metadata) RemovePath(path uint32) {
	m.RemoveWallet(uint64(path))
}

func sortInsertPos(wallets []uint64, id uint64) int {
	low, high := 0, len(wallets)
	for low < high {
		mid := (low + high) / 2
		if wallets[mid] < id {
			low = mid + 1
		} else {
			high = mid
		}
	}
	return low
}

func sortSearchPos(wallets []uint64, id uint64) int {
	low, high := 0, len(wallets)
	for low < high {
		mid := (low + high) / 2
		if wallets[mid] < id {
			low = mid + 1
		} else {
			high = mid
		}
	}
	return low
}

func (m *Metadata) Serialize() []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x20 | byte(len(m.name)))
	buf.WriteString(m.name)

	if len(m.wallets) == 0 {
		return buf.Bytes()
	}

	// Compress wallets into contiguous ranges
	type rangeEntry struct {
		start uint64
		count uint64
	}
	var ranges []rangeEntry
	start := m.wallets[0]
	count := uint64(0)

	for i := 1; i < len(m.wallets); i++ {
		w := m.wallets[i]
		if w == start+count+1 {
			count++
		} else {
			ranges = append(ranges, rangeEntry{start, count})
			count = 0
			start = w
		}
	}
	ranges = append(ranges, rangeEntry{start, count})

	// Encode ranges using BER length encoding
	for _, r := range ranges {
		buf.Write(tlv.EncodeBerLength(uint32(r.start)))
		buf.Write(tlv.EncodeBerLength(uint32(r.count)))
	}

	return buf.Bytes()
}
