package scryptlib

import (
	"bytes"
	"fmt"
	"math/big"
)

func (intType Int) StateHex() (string, error) {
	b, err := intType.StateBytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (intType Int) StateBytes() ([]byte, error) {
	var res []byte

	if intType.value.Cmp(big.NewInt(0)) == 0 {
		return []byte{0x01, 0x00}, nil
	}
	absVal := big.NewInt(0).Abs(intType.value)
	item := BigIntToBytes_LE(absVal)
	if (item[len(item)-1] & 0x80) != 0x00 {
		if intType.value.Sign() == -1 {
			item = append(item, 0x80)
		} else {
			item = append(item, 0x00)
		}
	} else if intType.value.Sign() == -1 {
		newByte := item[len(item)-1] | 0x80
		item = append(item[:len(item)-1], newByte)
	}

	b, err := appendPushdataPrefix(item)
	if err != nil {
		return res, err
	}
	return b, nil
}

func (boolType Bool) StateHex() (string, error) {
	b, err := boolType.StateBytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (boolType Bool) StateBytes() ([]byte, error) {
	if boolType.value {
		return []byte{0x01}, nil
	}
	return []byte{0x00}, nil
}

func (byteType Bytes) StateHex() (string, error) {
	return byteType.Hex()
}

func (byteType Bytes) StateBytes() ([]byte, error) {
	return byteType.Bytes()
}

func (privKeyType PrivKey) StateHex() (string, error) {
	b, err := privKeyType.StateBytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (privKeyType PrivKey) StateBytes() ([]byte, error) {

	if privKeyType.value == nil {
		return []byte{0x01, 0x00}, nil
	}

	return privKeyType.Bytes()
}

func (pubKeyType PubKey) StateHex() (string, error) {
	b, err := pubKeyType.StateBytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (pubKeyType PubKey) StateBytes() ([]byte, error) {

	if pubKeyType.value == nil {
		return []byte{0x01, 0x00}, nil
	}

	return pubKeyType.Bytes()
}

func (sigType Sig) StateHex() (string, error) {
	b, err := sigType.StateBytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (sigType Sig) StateBytes() ([]byte, error) {

	if sigType.value == nil {
		return []byte{0x01, 0x00}, nil
	}

	return sigType.Bytes()
}

func (ripemd160Type Ripemd160) StateHex() (string, error) {
	return ripemd160Type.Hex()
}

func (ripemd160Type Ripemd160) StateBytes() ([]byte, error) {
	return ripemd160Type.Bytes()
}

func (sha1Type Sha1) StateHex() (string, error) {
	return sha1Type.Hex()
}

func (sha1Type Sha1) StateBytes() ([]byte, error) {
	return sha1Type.Bytes()
}

func (sha256Type Sha256) StateHex() (string, error) {
	return sha256Type.Hex()
}

func (sha256Type Sha256) StateBytes() ([]byte, error) {
	return sha256Type.Bytes()
}

func (sigHashType SigHashType) StateHex() (string, error) {
	return sigHashType.Hex()
}

func (sigHashType SigHashType) StateBytes() ([]byte, error) {
	return sigHashType.Bytes()
}

func (sigHashPreimageType SigHashPreimage) StateHex() (string, error) {
	return sigHashPreimageType.Hex()
}

func (sigHashPreimageType SigHashPreimage) StateBytes() ([]byte, error) {
	return sigHashPreimageType.Bytes()
}

func (opCodeType OpCodeType) StateHex() (string, error) {
	return opCodeType.Hex()
}

func (opCodeType OpCodeType) StateBytes() ([]byte, error) {
	return opCodeType.Bytes()
}

func (arrayType Array) StateHex() (string, error) {
	b, err := arrayType.StateBytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (arrayType Array) StateBytes() ([]byte, error) {
	var res []byte
	var buff bytes.Buffer
	for _, elem := range arrayType.values {
		b, err := elem.StateBytes()
		if err != nil {
			return res, err
		}
		buff.Write(b)
	}
	return buff.Bytes(), nil
}

func (structType Struct) StateHex() (string, error) {
	b, err := structType.StateBytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (structType Struct) StateBytes() ([]byte, error) {
	var res []byte
	var buff bytes.Buffer
	for _, key := range structType.keysInOrder {
		elem := structType.values[key]
		b, err := elem.StateBytes()
		if err != nil {
			return res, err
		}
		buff.Write(b)
	}
	return buff.Bytes(), nil
}

func (libraryType Library) StateHex() (string, error) {
	b, err := libraryType.StateBytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (libraryType Library) StateBytes() ([]byte, error) {
	var res []byte
	var buff bytes.Buffer
	for _, key := range libraryType.propertyKeysInOrder {
		elem := libraryType.properties[key]
		b, err := elem.StateBytes()
		if err != nil {
			return res, err
		}
		buff.Write(b)
	}
	return buff.Bytes(), nil
}

func (hashedMapType HashedMap) StateHex() (string, error) {
	return hashedMapType.Hex()
}

func (hashedMapType HashedMap) StateBytes() ([]byte, error) {
	return hashedMapType.Bytes()
}
