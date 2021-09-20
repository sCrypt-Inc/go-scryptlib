package scryptlib


import (
    "fmt"
    "strings"
    "math/big"

    "github.com/libsv/go-bt/bscript"
    "github.com/libsv/go-bk/bec"
)


var BASIC_SCRYPT_TYPES = map[string]bool{
    "bool": true,
    "int": true,
    "bytes": true,
    "PubKey": true,
    "Sig": true,
    "Ripemd160": true,
    "Sha1": true,
    "Sha256": true,
    "SigHashType": true,
    "SigHashPreimage": true,
    "OpCodeType": true,
}

type ScryptType interface {
//    ASM() string
    Hex() (string, error)
}

type Int struct {
    value *big.Int
}

//func (intType Int) ASM() (string, error) {
//    s, err := bscript.NewFromHexString(bigIntToHex_LE(intType.value))
//    if err != nil {
//        return "", err
//    }
//    asm, err := s.ToASM()
//    if err != nil {
//        return "", err
//    }
//    return asm, nil
//}

func (intType Int) Hex() (string, error) {
    if intType.value.Cmp(big.NewInt(0)) == 0 {
        // If val == 0.
        return "00", nil
    } else if intType.value.Cmp(big.NewInt(0)) == 1 &&
              intType.value.Cmp(big.NewInt(17)) == -1 {
        // If 0 < val <= 16.
        var val int64 = 80
        val += intType.value.Int64()
        return fmt.Sprintf("%x", val), nil
    }


    b := bigIntToBytes_LE(intType.value)
    if b[len(b)-1] & 0x80 > 1 {
        if intType.value.Cmp(big.NewInt(0)) == -1 {
            b = append(b, 0x80)
        } else {
            b = append(b, 0x00)
        }
    }
    pushDataPrefix, err := bscript.GetPushDataPrefix(b)
    if err != nil {
        return "", err
    }

    return evenHexStr(fmt.Sprintf("%x%x", pushDataPrefix, b)), nil
}

type Bool struct {
    value bool
}

func (boolType Bool) Hex() (string, error) {
    if boolType.value == true {
        return "51", nil
    }
    return "00", nil
}

type Bytes struct {
    value []byte
}

func (bytesType Bytes) Hex() (string, error) {
    pushDataPrefix, err := bscript.GetPushDataPrefix(bytesType.value)
    if err != nil {
        return "", err
    }
    return evenHexStr(fmt.Sprintf("%x%x", pushDataPrefix, bytesType.value)), nil
}

type PrivKey struct {
    value bec.PrivateKey
}

func (privKeyType PrivKey) Hex() (string, error) {
    b := privKeyType.value.Serialise()
    return evenHexStr(fmt.Sprintf("%x", b)), nil
}

type PubKey struct {
    value bec.PublicKey
}

func (pubKeyType PubKey) Hex() (string, error) {
    b := pubKeyType.value.SerialiseCompressed()
    return evenHexStr(fmt.Sprintf("%x", b)), nil
}

type Sig struct {
    value bec.Signature
}

func (sigType Sig) Hex() (string, error) {
    b := sigType.value.Serialise()
    return evenHexStr(fmt.Sprintf("%x", b)), nil
}

type Ripemd160 struct {
    value [20]byte
}

func (ripemd160Type Ripemd160) Hex() (string, error) {
    return evenHexStr(fmt.Sprintf("%x", ripemd160Type.value)), nil
}

type Sha1 struct {
    value [20]byte
}

func (sha1Type Sha1) Hex() (string, error) {
    return evenHexStr(fmt.Sprintf("%x", sha1Type.value)), nil
}

type Sha256 struct {
    value [32]byte
}

func (sha256Type Sha256) Hex() (string, error) {
    return evenHexStr(fmt.Sprintf("%x", sha256Type.value)), nil
}

type SigHashType struct {
    value []byte
}

func (sigHashType SigHashType) Hex() (string, error) {
    return evenHexStr(fmt.Sprintf("%x", sigHashType.value)), nil
}

type SigHashPreimage struct {
    value []byte
}

func (sigHashPreimageType SigHashPreimage) Hex() (string, error) {
    return evenHexStr(fmt.Sprintf("%x", sigHashPreimageType.value)), nil
}

type OpCodeType struct {
    value []byte
}

func (opCodeType OpCodeType) Hex() (string, error) {
    return evenHexStr(fmt.Sprintf("%x", opCodeType.value)), nil
}

type Array struct {
    value []ScryptType
}

func (arrayType Array) Hex() (string, error) {
    var b strings.Builder
    for _, elem := range arrayType.value {
        hex, err := elem.Hex()
        if err != nil {
            return "", err
        }
        b.WriteString(hex)
    }
    return b.String(), nil
}

type Struct struct {
    keysInOrder []string
    value map[string]ScryptType
}

func (structType Struct) Hex() (string, error) {
    var b strings.Builder
    for _, key := range structType.keysInOrder {
        elem := structType.value[key]
        hex, err := elem.Hex()
        if err != nil {
            return "", err
        }
        b.WriteString(hex)
    }
    return b.String(), nil
}

