package scryptlib

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStateHexInt(t *testing.T) {
	inputs := []int64{0, 1, 2, 16, 500, -1, -2, -16, -500}
	outputs := []string{
		"0100",
		"0101",
		"0102",
		"0110",
		"02f401",
		"0181",
		"0182",
		"0190",
		"02f481",
	}

	for i := 0; i < len(inputs); i++ {
		hex, err := Int{big.NewInt(inputs[i])}.StateHex()
		assert.NoError(t, err)
		assert.Equal(t, outputs[i], hex)
	}

	hugeBigInt := big.NewInt(0).Exp(big.NewInt(123), big.NewInt(20), nil)
	hex, err := Int{hugeBigInt}.StateHex()
	assert.NoError(t, err)
	assert.Equal(t, "1231f4793b58adb13501451036091bd4213607", hex)
}

func TestStateHexBool(t *testing.T) {
	hex, err := Bool{true}.StateHex()
	assert.NoError(t, err)
	assert.Equal(t, "01", hex)

	hex, err = Bool{false}.StateHex()
	assert.NoError(t, err)
	assert.Equal(t, "00", hex)
}

func TestStateHexBytes(t *testing.T) {
	inputs := [][]byte{
		{0x00},
		{0x00, 0xff},
		{0xff, 0xab, 0xbc, 0x00},
	}
	outputs := []string{
		"0100",
		"0200ff",
		"04ffabbc00",
	}

	for i := 0; i < len(inputs); i++ {
		hex, err := Bytes{inputs[i]}.StateHex()
		assert.NoError(t, err)
		assert.Equal(t, outputs[i], hex)
	}

	// OP_PUSHDATA teritory
	var pushdataSizes = []int{76, 256, 65536}
	var pushdataPrefixes = []string{"4c4c", "4d0001", "4e00000100"}
	for i, size := range pushdataSizes {
		pushdata1Input := make([]byte, size)
		pushdata1Out := pushdataPrefixes[i]
		for j := 0; j < size; j++ {
			pushdata1Out += "00"
		}

		hex, err := Bytes{pushdata1Input}.StateHex()
		assert.NoError(t, err)
		assert.Equal(t, pushdata1Out, hex)
	}

}
