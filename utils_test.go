package scryptlib

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStructCompare(t *testing.T) {
	personKeysInOrder := []string{"name", "nicknames", "height", "dog"}
	dogKeysInOrder := []string{"name", "breed"}

	dog0Name := Bytes{[]byte("Rex")}
	dog0Breed := Bytes{[]byte("Beagle")}
	dog0Values := map[string]ScryptType{
		"name":  dog0Name,
		"breed": dog0Breed,
	}
	dog0 := Struct{
		keysInOrder: dogKeysInOrder,
		values:      dog0Values,
	}

	person0Name := Bytes{[]byte("Alice")}
	var person0NicknamesVals []ScryptType
	person0NicknamesVals = append(person0NicknamesVals, Bytes{[]byte("Alie")})
	person0NicknamesVals = append(person0NicknamesVals, Bytes{[]byte("A")})
	person0Nicknames := Array{person0NicknamesVals}
	person0Height := Int{big.NewInt(192)}
	person0Values := map[string]ScryptType{
		"name":      person0Name,
		"nicknames": person0Nicknames,
		"height":    person0Height,
		"dog":       dog0,
	}
	person0 := Struct{
		keysInOrder: personKeysInOrder,
		values:      person0Values,
	}

	res0 := IsStructsSameStructure(dog0, person0)
	assert.Equal(t, res0, false)

	res1 := IsStructsSameStructure(person0, person0)
	assert.Equal(t, res1, true)

	res2 := IsStructsSameStructure(dog0, dog0)
	assert.Equal(t, res2, true)

	res3 := IsStructsSameStructure(person0, dog0)
	assert.Equal(t, res3, false)
}

func Test_num2bin(t *testing.T) {

	hex, _ := num2bin(Int{big.NewInt(0)}, 3)

	assert.Equal(t, hex, "000000")

	hex, _ = num2bin(Int{big.NewInt(10)}, 1)

	assert.Equal(t, hex, "0a")

	hex, _ = num2bin(Int{big.NewInt(0x123)}, 2)

	assert.Equal(t, hex, "2301")

	hex, _ = num2bin(Int{big.NewInt(0x123456789abcde)}, 7)

	assert.Equal(t, hex, "debc9a78563412")

	hex, _ = num2bin(Int{big.NewInt(-1000)}, 2)

	assert.Equal(t, hex, "e883")

	hex, _ = num2bin(Int{big.NewInt(0x123456789abcde)}, 10)

	assert.Equal(t, hex, "debc9a78563412000000")

	hex, _ = num2bin(Int{big.NewInt(-1000)}, 4)

	assert.Equal(t, hex, "e8030080")

	hex, _ = num2bin(Int{big.NewInt(-123456789)}, 8)

	assert.Equal(t, hex, "15cd5b0700000080")

}

func Test_flattenSha256(t *testing.T) {

	pkh, _ := NewPubKeyHash("7544770a4f91feef04c35d90190b1d4eb4fbe4c0")
	s, _ := FlattenSHA256(pkh)

	assert.Equal(t, hex.EncodeToString(s[:]), "f1cad1c1958e36c48e81ad86ce2cafda0f509a5872af8354d29cd69609ab8e73")

	s, _ = FlattenSHA256(Int{big.NewInt(0)})

	assert.Equal(t, hex.EncodeToString(s[:]), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	s, _ = FlattenSHA256(Bool{false})

	assert.Equal(t, hex.EncodeToString(s[:]), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	e := make([]byte, 0)
	s, _ = FlattenSHA256(NewBytes(e))

	assert.Equal(t, hex.EncodeToString(s[:]), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	s, _ = FlattenSHA256(Int{big.NewInt(1)})

	assert.Equal(t, hex.EncodeToString(s[:]), "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a")

	s, _ = FlattenSHA256(NewHashedMap())

	assert.Equal(t, hex.EncodeToString(s[:]), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	m := NewHashedMap()
	m.Set(Int{big.NewInt(1)}, Int{big.NewInt(11)})

	h, _ := m.Hex()

	assert.Equal(t, h, "404bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459ae7cf46a078fed4fafd0b5e3aff144802b853f8ae459a4f0c14add3314b7cc3a6")

}

func Test_ParseGenericType(t *testing.T) {
	name, ts := ParseGenericType("L<int>")
	assert.Equal(t, name, "L")
	assert.Equal(t, ts, []string{"int"})

	name, ts = ParseGenericType("HashedMap<int, int>")
	assert.Equal(t, name, "HashedMap")
	assert.Equal(t, ts, []string{"int", "int"})

	name, ts = ParseGenericType("HashedMap<int, bytes>")
	assert.Equal(t, name, "HashedMap")
	assert.Equal(t, ts, []string{"int", "bytes"})

	name, ts = ParseGenericType("Mylib<int, bool >")
	assert.Equal(t, name, "Mylib")
	assert.Equal(t, ts, []string{"int", "bool"})

	name, ts = ParseGenericType("LL<int, ST1>")
	assert.Equal(t, name, "LL")
	assert.Equal(t, ts, []string{"int", "ST1"})

	name, ts = ParseGenericType("ST0<ST0<int,int>,int>")
	assert.Equal(t, name, "ST0")
	assert.Equal(t, ts, []string{"ST0<int,int>", "int"})
}

func Test_FactorizeArrayTypeString(t *testing.T) {
	typeName, arraySizes := FactorizeArrayTypeString("L<int>[2][2]")
	assert.Equal(t, typeName, "L<int>")
	assert.Equal(t, arraySizes, []string{"2", "2"})

	typeName, arraySizes = FactorizeArrayTypeString("ST1<ST0<ST2[3]>>[2]")
	assert.Equal(t, typeName, "ST1<ST0<ST2[3]>>")
	assert.Equal(t, arraySizes, []string{"2"})

}

func Test_LoadDesc(t *testing.T) {
	desc, err := LoadDesc("desc/demo_desc.json")

	assert.NoError(t, err)

	contractDemo, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	x := Int{big.NewInt(7)}
	y := Int{big.NewInt(4)}
	constructorParams := map[string]ScryptType{
		"x": x,
		"y": y,
	}

	err = contractDemo.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	sumCorrect := Int{big.NewInt(11)}
	addParams := map[string]ScryptType{
		"z": sumCorrect,
	}
	err = contractDemo.SetPublicFunctionParams("add", addParams)
	assert.NoError(t, err)

	success, err := contractDemo.EvaluatePublicFunction("add")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

}
