package x

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGenerateKeyPairs(t *testing.T) {
	t.Run("case=generate key pairs", func(t *testing.T) {
		privKey, pubKey, err := GenerateKey()
		require.NoError(t, err)
		msg := "hello,world!"
		signed, err := Sign([]byte(msg), privKey)
		require.NoError(t, err)
		err = Verify([]byte(msg), signed, pubKey)
		require.NoError(t, err)
	})
}
