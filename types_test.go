package scryptlib

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTypesInt(t *testing.T) {
	bigIntObj := big.NewInt(0)
	intObj := Int{value: bigIntObj}
	hex, _ := intObj.Hex()
	assert.Equal(t, "00", hex)

	bigIntObj = big.NewInt(1)
	intObj = Int{value: bigIntObj}
	hex, _ = intObj.Hex()
	assert.Equal(t, "51", hex)

	bigIntObj = big.NewInt(16)
	intObj = Int{value: bigIntObj}
	hex, _ = intObj.Hex()
	assert.Equal(t, "60", hex)

	bigIntObj = big.NewInt(17)
	intObj = Int{value: bigIntObj}
	hex, _ = intObj.Hex()
	assert.Equal(t, "0111", hex)

	bigIntObj = big.NewInt(129)
	intObj = Int{value: bigIntObj}
	hex, _ = intObj.Hex()
	assert.Equal(t, "028100", hex)

	bigIntObj = big.NewInt(-243)
	intObj = Int{value: bigIntObj}
	hex, _ = intObj.Hex()
	assert.Equal(t, "02f380", hex)
}

func TestTypesHashedMap(t *testing.T) {
	hm := NewHashedMap()
	hm.Set(Int{big.NewInt(22)}, Bytes{[]byte{0xf1}})
	hm.Set(Int{big.NewInt(3)}, Bytes{[]byte{0x99}})
	hm.Set(Int{big.NewInt(1234)}, Bytes{[]byte{0xf1, 0xff}})

	keyIdx, err := hm.KeyIndex(Int{big.NewInt(1234)})
	assert.NoError(t, err)
	assert.Equal(t, 2, keyIdx)

	keyIdx, err = hm.KeyIndex(Int{big.NewInt(22)})
	assert.NoError(t, err)
	assert.Equal(t, 1, keyIdx)

	keyIdx, err = hm.KeyIndex(Int{big.NewInt(3)})
	assert.NoError(t, err)
	assert.Equal(t, 0, keyIdx)

	hex, _ := hm.Hex()
	assert.Equal(t, "084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5fd9528b920d6d3956e9e16114523e1889c751e8c1e040182116d4c906b43f5587cb7c4547cf2653590d7a9ace60cc623d25148adfbc88a89aeb0ef88da7839bad4f09e5c5af99a24c7e304ca7997d26cb00901697de08a49be0d46ab5839b614806505393e046db3163e748c7c7ee1763d242f1f7815a0aaa32c211916df6f0438999152af10c421ddd26ea0baa3ad39ac02d45108d0bd2a6689321273293632", hex)

	// TODO: Test with struct types.
}
