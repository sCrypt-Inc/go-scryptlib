package scryptlib


import (
    "fmt"
    "strings"
    "math/big"

    "github.com/libsv/go-bt/v2/bscript"
    "github.com/libsv/go-bk/bec"
)


var BASIC_SCRYPT_TYPES = map[string]bool{
    "bool": true,
    "int": true,
    "bytes": true,
    "PrivKey": true,
    "PubKey": true,
    "Sig": true,
    "Ripemd160": true,
    "Sha1": true,
    "Sha256": true,
    "SigHashType": true,
    "SigHashPreimage": true,
    "OpCodeType": true,
}

// TODO: Should sCrypt types have pointer method receivers instead of value ones? 
//       Would reduce memory print when calling methods of large struct or array structs, but is it worth it?

type ScryptType interface {
    Hex()           (string, error)
    GetTypeString() string
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


    b := BigIntToBytes_LE(intType.value)
    if b[len(b)-1] & 0x80 > 1 {
        if intType.value.Cmp(big.NewInt(0)) == -1 {
            b = append(b, 0x80)
        } else {
            b = append(b, 0x00)
        }
    }
    pushDataPrefix, err := bscript.PushDataPrefix(b)
    if err != nil {
        return "", err
    }

    return EvenHexStr(fmt.Sprintf("%x%x", pushDataPrefix, b)), nil
}

func (intType Int) GetTypeString() string {
    return "int"
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

func (boolType Bool) GetTypeString() string {
    return "bool"
}

type Bytes struct {
    value []byte
}

func (bytesType Bytes) Hex() (string, error) {
    pushDataPrefix, err := bscript.PushDataPrefix(bytesType.value)
    if err != nil {
        return "", err
    }
    return EvenHexStr(fmt.Sprintf("%x%x", pushDataPrefix, bytesType.value)), nil
}

func (bytesType Bytes) GetTypeString() string {
    return "bytes"
}

type PrivKey struct {
    value *bec.PrivateKey
}

func (privKeyType PrivKey) Hex() (string, error) {
    b := privKeyType.value.Serialise()
    return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (privKeyType PrivKey) GetTypeString() string {
    return "PrivKey"
}

type PubKey struct {
    value *bec.PublicKey
}

func (pubKeyType PubKey) Hex() (string, error) {
    b := pubKeyType.value.SerialiseCompressed()
    return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (pubKeyType PubKey) GetTypeString() string {
    return "PubKey"
}

type Sig struct {
    value *bec.Signature
}

func (sigType Sig) Hex() (string, error) {
    b := sigType.value.Serialise()
    return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (sigType Sig) GetTypeString() string {
    return "Sig"
}

type Ripemd160 struct {
    // TODO: Should value be fixed size byte array instead?
    value []byte
}

func (ripemd160Type Ripemd160) Hex() (string, error) {
    return EvenHexStr(fmt.Sprintf("%x", ripemd160Type.value)), nil
}

func (ripemd160Type Ripemd160) GetTypeString() string {
    return "Ripemd160"
}

type Sha1 struct {
    // TODO: Should value be fixed size byte array instead?
    value []byte
}

func (sha1Type Sha1) Hex() (string, error) {
    return EvenHexStr(fmt.Sprintf("%x", sha1Type.value)), nil
}

func (sha1 Sha1) GetTypeString() string {
    return "Sha1"
}

type Sha256 struct {
    // TODO: Should value be fixed size byte array instead?
    value []byte
}

func (sha256Type Sha256) Hex() (string, error) {
    return EvenHexStr(fmt.Sprintf("%x", sha256Type.value)), nil
}

func (sha256 Sha256) GetTypeString() string {
    return "Sha256"
}

type SigHashType struct {
    value []byte
}

func (sigHashType SigHashType) Hex() (string, error) {
    return EvenHexStr(fmt.Sprintf("%x", sigHashType.value)), nil
}

func (sigHashType SigHashType) GetTypeString() string {
    return "SigHashType"
}

type SigHashPreimage struct {
    value []byte
}

func (sigHashPreimageType SigHashPreimage) Hex() (string, error) {
    return EvenHexStr(fmt.Sprintf("%x", sigHashPreimageType.value)), nil
}

func (sigHashPreimage SigHashPreimage) GetTypeString() string {
    return "SigHashPreimage"
}

type OpCodeType struct {
    value []byte
}

func (opCodeType OpCodeType) Hex() (string, error) {
    return EvenHexStr(fmt.Sprintf("%x", opCodeType.value)), nil
}

func (opCodeType OpCodeType) GetTypeString() string {
    return "OpCodeType"
}

type Array struct {
    values []ScryptType
}

func (arrayType Array) Hex() (string, error) {
    var b strings.Builder
    for _, elem := range arrayType.values {
        hex, err := elem.Hex()
        if err != nil {
            return "", err
        }
        b.WriteString(hex)
    }
    return b.String(), nil
}

func (arrayType Array) GetTypeString() string {
    return ""
}

type Struct struct {
    keysInOrder []string
    values map[string]ScryptType
}

func (structType Struct) Hex() (string, error) {
    var b strings.Builder
    for _, key := range structType.keysInOrder {
        elem := structType.values[key]
        hex, err := elem.Hex()
        if err != nil {
            return "", err
        }
        b.WriteString(hex)
    }
    return b.String(), nil
}

func (structType Struct) GetTypeString() string {
    return ""
}

// TODO: Function for creating structs

