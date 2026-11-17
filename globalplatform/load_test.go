package globalplatform

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capFile writes a CAP archive holding the given components and returns it open for the
// duration of the test.
func capFile(t *testing.T, files map[string][]byte) *os.File {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.cap")
	out, err := os.Create(path)
	require.NoError(t, err)

	zipWriter := zip.NewWriter(out)

	for _, name := range internalFiles {
		data, ok := files[name]
		if !ok {
			continue
		}

		w, err := zipWriter.Create(name)
		require.NoError(t, err)

		_, err = w.Write(data)
		require.NoError(t, err)
	}

	require.NoError(t, zipWriter.Close())
	require.NoError(t, out.Close())

	f, err := os.Open(path)
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, f.Close())
	})

	return f
}

func TestNewLoadCommandStream_BadBlockSize(t *testing.T) {
	file := capFile(t, map[string][]byte{"Header": []byte{0x01}})

	for _, blockSize := range []int{0, -1, 256} {
		_, err := NewLoadCommandStream(file, blockSize)
		assert.Error(t, err, "block size %d", blockSize)
	}
}

// The blocks of a load must fit the data field left by the secure channel, which is
// smaller than an APDU as soon as a MAC is appended or the data is encrypted.
func TestLoadCommandStream_Blocks(t *testing.T) {
	tests := []struct {
		name      string
		blockSize int
		component int
	}{
		{"mac only level", 247, 500},
		{"encrypted level", 223, 500},
		{"one block", 247, 10},
		{"exact multiple", 16, 45},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			component := bytes.Repeat([]byte{0xAB}, test.component)
			file := capFile(t, map[string][]byte{"Header": component})

			stream, err := NewLoadCommandStream(file, test.blockSize)
			require.NoError(t, err)

			payload := append([]byte{tagLoadFileDataBlock}, encodeLength(len(component))...)
			payload = append(payload, component...)

			var (
				got     []byte
				blocks  int
				lastP1  byte
				lastLen int
			)

			for stream.Next() {
				cmd := stream.GetCommand()

				assert.Equal(t, byte(InsLoad), cmd.Ins)
				assert.Equal(t, byte(blocks), cmd.P2)
				assert.LessOrEqual(t, len(cmd.Data), test.blockSize, "block %d overflows the channel", blocks)

				got = append(got, cmd.Data...)
				lastP1 = cmd.P1
				lastLen = len(cmd.Data)
				blocks++
			}

			wantBlocks := (len(payload) + test.blockSize - 1) / test.blockSize
			assert.Equal(t, wantBlocks, blocks)
			assert.Equal(t, wantBlocks, stream.BlocksCount())
			assert.Equal(t, payload, got)
			assert.Equal(t, len(payload)-(wantBlocks-1)*test.blockSize, lastLen)
			assert.Equal(t, byte(P1LoadLastBlock), lastP1, "only the last block closes the load")
		})
	}
}

func TestLoadCommandStream_BlockIndexes(t *testing.T) {
	file := capFile(t, map[string][]byte{"Header": bytes.Repeat([]byte{0x01}, 40)})

	stream, err := NewLoadCommandStream(file, 20)
	require.NoError(t, err)

	var indexes []byte

	for stream.Next() {
		indexes = append(indexes, stream.GetCommand().P2)
	}

	assert.Equal(t, []byte{0, 1, 2}, indexes)
}

// The components the card expects are read in a fixed order and the others are ignored.
func TestLoadCommandStream_InternalFilesOrder(t *testing.T) {
	file := capFile(t, map[string][]byte{
		"Class":         []byte{0xCC},
		"Header":        []byte{0x01},
		"SomethingElse": []byte{0xEE},
	})

	stream, err := NewLoadCommandStream(file, 255)
	require.NoError(t, err)

	require.True(t, stream.Next())
	assert.Equal(t, []byte{tagLoadFileDataBlock, 0x02, 0x01, 0xCC}, stream.GetCommand().Data)
	assert.False(t, stream.Next())
}
