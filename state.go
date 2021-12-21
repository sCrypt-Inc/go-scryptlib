package scryptlib


import (
    "fmt"
    "bytes"
    "math/big"
)


func SerialiseContractState(vals []ScryptType) ([]byte, error) {
    var res []byte
    var buff bytes.Buffer

    for _, val := range vals {
        stateBytes, err := val.StateBytes()
        if err != nil {
            return res, err
        }
        buff.Write(stateBytes)
    }

    return buff.Bytes(), nil
}

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
    if (item[len(item) - 1] & 0x80) != 0x00 {
        if intType.value.Sign() == -1 {
            item = append(item, 0x80)
        } else {
            item = append(item, 0x00)
        }
    } else if intType.value.Sign() == -1 {
        newByte := item[len(item) - 1] | 0x80
        item = append(item[:len(item) - 1], newByte)
    }

    b, err := appendPushdataPrefix(item)
    if err != nil {
        return res, err
    }
    return b, nil

    return item, nil
}

func (boolType Bool) StateHex() (string, error) {
    return boolType.Hex()
}

func (boolType Bool) StateBytes() ([]byte, error) {
    return boolType.Bytes()
}

func (byteType Bytes) StateHex() (string, error) {
    return byteType.Hex()
}

func (byteType Bytes) StateBytes() ([]byte, error) {
    return byteType.Bytes()
}

func (privKeyType PrivKey) StateHex() (string, error) {
    return privKeyType.Hex()
}

func (privKeyType PrivKey) StateBytes() ([]byte, error) {
    return privKeyType.Bytes()
}

func (pubKeyType PubKey) StateHex() (string, error) {
    return pubKeyType.Hex()
}

func (pubKeyType PubKey) StateBytes() ([]byte, error) {
    return pubKeyType.Bytes()
}

func (sigType Sig) StateHex() (string, error) {
    return sigType.Hex()
}

func (sigType Sig) StateBytes() ([]byte, error) {
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
    return arrayType.Hex()
}

func (arrayType Array) StateBytes() ([]byte, error) {
    return arrayType.Bytes()
}

func (structType Struct) StateHex() (string, error) {
    return structType.Hex()
}

func (structType Struct) StateBytes() ([]byte, error) {
    return structType.Bytes()
}

func (hashedMapType HashedMap) StateHex() (string, error) {
    return hashedMapType.Hex()
}

func (hashedMapType HashedMap) StateBytes() ([]byte, error) {
    return hashedMapType.Bytes()
}

