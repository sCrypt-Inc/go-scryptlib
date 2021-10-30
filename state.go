package scryptlib


import (
    "fmt"
    "strings"
    "math/big"
)


func SerialiseContractState(vals []ScryptType) (string, error) {
    var sb strings.Builder

    for _, val := range vals {
        stateHex, err := val.StateHex()
        if err != nil {
            return "", err
        }
        sb.WriteString(stateHex)
    }

    return sb.String(), nil
}

func (intType Int) StateHex() (string, error) {
    if intType.value.Cmp(big.NewInt(0)) == 0 {
        return "0100", nil
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

    item, err := appendPushdataPrefix(item)
    if err != nil {
        return "", err
    }

    return fmt.Sprintf("%x", item), nil
}

func (boolType Bool) StateHex() (string, error) {
    return boolType.Hex()
}

func (bytesType Bytes) StateHex() (string, error) {
    return bytesType.Hex()
}

func (privKeyType PrivKey) StateHex() (string, error) {
    return privKeyType.Hex()
}

func (pubKeyType PubKey) StateHex() (string, error) {
    return pubKeyType.Hex()
}

func (sigType Sig) StateHex() (string, error) {
    return sigType.Hex()
}

func (ripemd160Type Ripemd160) StateHex() (string, error) {
    return ripemd160Type.Hex()
}

func (sha1Type Sha1) StateHex() (string, error) {
    return sha1Type.Hex()
}

func (sha256Type Sha256) StateHex() (string, error) {
    return sha256Type.Hex()
}

func (sigHashType SigHashType) StateHex() (string, error) {
    return sigHashType.Hex()
}

func (sigHashPreimageType SigHashPreimage) StateHex() (string, error) {
    return sigHashPreimageType.Hex()
}

func (opCodeType OpCodeType) StateHex() (string, error) {
    return opCodeType.Hex()
}

func (arrayType Array) StateHex() (string, error) {
    return arrayType.Hex()
}

func (structType Struct) StateHex() (string, error) {
    return structType.Hex()
}
