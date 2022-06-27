package scryptlib

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/libsv/go-bk/base58"
	"github.com/libsv/go-bk/bec"
	"github.com/libsv/go-bt/v2/bscript"
	"github.com/libsv/go-bt/v2/sighash"
)

var BASIC_SCRYPT_TYPES = map[string]bool{
	"bool":            true,
	"int":             true,
	"bytes":           true,
	"PrivKey":         true,
	"PubKey":          true,
	"Sig":             true,
	"Ripemd160":       true,
	"Sha1":            true,
	"Sha256":          true,
	"SigHashType":     true,
	"SigHashPreimage": true,
	"OpCodeType":      true,
}

// TODO: Should sCrypt types have pointer method receivers instead of value ones?
//       Would reduce memory print when calling methods of large struct or array structs, but is it worth it?

type ScryptType interface {
	Hex() (string, error)
	Bytes() ([]byte, error)
	GetTypeString() string
	StateHex() (string, error)
	StateBytes() ([]byte, error)
}

type Int struct {
	value *big.Int
}

func NewInt(val int64) Int {
	return Int{big.NewInt(val)}
}

func (intType Int) Clone() Int {
	return Int{intType.value}
}

func (intType Int) Hex() (string, error) {
	b, err := intType.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (intType Int) Bytes() ([]byte, error) {
	var res []byte

	if intType.value.Cmp(big.NewInt(0)) == 0 {
		// If val == 0.
		return []byte{0x00}, nil
	} else if intType.value.Cmp(big.NewInt(0)) == 1 &&
		intType.value.Cmp(big.NewInt(17)) == -1 {
		// If 0 < val <= 16.
		var val int64 = 80
		val += intType.value.Int64()

		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(val))
		return b[0:1], nil
	}

	b := BigIntToBytes_LE(intType.value)
	if b[len(b)-1]&0x80 > 1 {
		if intType.value.Cmp(big.NewInt(0)) == -1 {
			b = append(b, 0x80)
		} else {
			b = append(b, 0x00)
		}
	}
	b, err := appendPushdataPrefix(b)
	if err != nil {
		return res, err
	}

	return b, nil
}

func (intType Int) GetTypeString() string {
	return "int"
}

func (intType Int) MarshalJSON() ([]byte, error) {
	return []byte("\"" + intType.value.String() + "\""), nil
}

type Bool struct {
	value bool
}

func NewBool(val bool) Bool {
	return Bool{val}
}

func (boolType Bool) Clone() Bool {
	return Bool{boolType.value}
}

func (boolType Bool) Hex() (string, error) {
	b, err := boolType.Bytes()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%02x", b), nil
}

func (boolType Bool) Bytes() ([]byte, error) {
	if boolType.value {
		return []byte{0x51}, nil
	}
	return []byte{0x00}, nil
}

func (boolType Bool) GetTypeString() string {
	return "bool"
}

func (boolType Bool) MarshalJSON() ([]byte, error) {

	if boolType.value {
		return []byte("true"), nil
	}

	return []byte("false"), nil
}

type Bytes struct {
	value []byte
}

func NewBytes(val []byte) Bytes {
	return Bytes{val}
}

func (bytesType Bytes) Hex() (string, error) {
	b, err := bytesType.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (bytesType Bytes) Bytes() ([]byte, error) {

	if bytesType.value == nil {
		return []byte{0x00}, nil
	}

	var res []byte
	pushDataPrefix, err := bscript.PushDataPrefix(bytesType.value)
	if err != nil {
		return res, err
	}
	return append(pushDataPrefix, bytesType.value...), nil
}

func (bytesType Bytes) GetTypeString() string {
	return "bytes"
}

func (bytesType Bytes) MarshalJSON() ([]byte, error) {

	if len(bytesType.value) == 0 {
		return []byte("\"b''\""), nil
	}

	l := fmt.Sprintf("\"b'%s'\"", hex.EncodeToString(bytesType.value))
	return []byte(l), nil
}

type PrivKey struct {
	value *bec.PrivateKey
}

func NewPrivKey(val *bec.PrivateKey) PrivKey {
	return PrivKey{val}
}

func (privKeyType PrivKey) Hex() (string, error) {
	b, err := privKeyType.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (privKeyType PrivKey) Bytes() ([]byte, error) {

	if privKeyType.value == nil {
		return []byte{0x00}, nil
	}

	var res []byte
	b := privKeyType.value.Serialise()

	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}

	pushDataPrefix, err := bscript.PushDataPrefix(b)
	if err != nil {
		return res, err
	}

	return append(pushDataPrefix, b...), nil
}

func (privKeyType PrivKey) GetTypeString() string {
	return "PrivKey"
}

func (privKeyType PrivKey) MarshalJSON() ([]byte, error) {

	if privKeyType.value == nil {
		return []byte("\"PrivKey(0)\""), nil
	}

	b := privKeyType.value.Serialise()
	n := new(big.Int)
	n.SetBytes(b)

	l := fmt.Sprintf("\"PrivKey(%s)\"", n.String())
	return []byte(l), nil
}

type PubKey struct {
	value *bec.PublicKey
}

func NewPubKey(val *bec.PublicKey) PubKey {
	return PubKey{val}
}

func (pubKeyType PubKey) Hex() (string, error) {
	b, err := pubKeyType.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (pubKeyType PubKey) Bytes() ([]byte, error) {

	if pubKeyType.value == nil {
		return []byte{0x00}, nil
	}

	res := make([]byte, 0)
	b := pubKeyType.value.SerialiseCompressed()
	pushDataPrefix, err := bscript.PushDataPrefix(b)
	if err != nil {
		return res, err
	}

	return append(pushDataPrefix, b...), nil
}

func (pubKeyType PubKey) GetTypeString() string {
	return "PubKey"
}

func (pubKeyType PubKey) MarshalJSON() ([]byte, error) {
	if pubKeyType.value == nil {
		return []byte("\"PubKey(b'')\""), nil
	}
	b := pubKeyType.value.SerialiseCompressed()
	l := fmt.Sprintf("\"PubKey(b'%s')\"", hex.EncodeToString(b))
	return []byte(l), nil
}

type Sig struct {
	value *bec.Signature
	shf   sighash.Flag
}

func (sigType Sig) Hex() (string, error) {
	b, err := sigType.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (sigType Sig) Bytes() ([]byte, error) {

	if sigType.value == nil {
		return []byte{0x00}, nil
	}

	var res []byte
	b := sigType.value.Serialise()
	b = append(b, byte(sigType.shf))
	pushDataPrefix, err := bscript.PushDataPrefix(b)
	if err != nil {
		return res, err
	}

	return append(pushDataPrefix, b...), nil
}

func (sigType Sig) GetTypeString() string {
	return "Sig"
}

func (sigType Sig) MarshalJSON() ([]byte, error) {
	b := sigType.value.Serialise()
	b = append(b, byte(sigType.shf))
	l := fmt.Sprintf("\"Sig(b'%s')\"", hex.EncodeToString(b))
	return []byte(l), nil
}

func NewSigFromDECBytes(sigBytes []byte, shf sighash.Flag) (Sig, error) {
	var res Sig
	value, err := bec.ParseDERSignature(sigBytes, bec.S256())
	if err != nil {
		return res, err
	}
	return Sig{value, shf}, nil
}

type Ripemd160 struct {
	// TODO: Should value be fixed size byte array instead?
	value []byte
}

func (ripemd160Type Ripemd160) Hex() (string, error) {
	b, err := ripemd160Type.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (ripemd160Type Ripemd160) Bytes() ([]byte, error) {

	if len(ripemd160Type.value) == 0 {
		return []byte{0x00}, nil
	}

	var res []byte
	b := ripemd160Type.value
	pushDataPrefix, err := bscript.PushDataPrefix(b)
	if err != nil {
		return res, err
	}

	return append(pushDataPrefix, b...), nil
}

func (ripemd160Type Ripemd160) GetTypeString() string {
	return "Ripemd160"
}

func (ripemd160Type Ripemd160) MarshalJSON() ([]byte, error) {

	b := ripemd160Type.value
	l := fmt.Sprintf("\"Ripemd160(b'%s')\"", hex.EncodeToString(b))
	return []byte(l), nil
}

func NewRipemd160FromBase58(value string) (Ripemd160, error) {
	var res Ripemd160
	if len(value) != 40 {
		return res, errors.New("Base58 string for Ripemd160 should be 40 characters long")
	}
	return Ripemd160{base58.Decode(value)}, nil
}

func NewPubKeyHash(value string) (Ripemd160, error) {
	var res Ripemd160
	if len(value) != 40 {
		return res, errors.New("hex string for PubKeyHash should be 40 characters long")
	}
	b, err := hex.DecodeString(value)

	if err != nil {
		return res, errors.New("invalid hex string for PubKeyHash")
	}
	return Ripemd160{b}, nil
}

type Sha1 struct {
	// TODO: Should value be fixed size byte array instead?
	value []byte
}

func NewSha1(val []byte) Sha1 {
	return Sha1{val}
}

func (sha1Type Sha1) Hex() (string, error) {
	b, err := sha1Type.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (sha1Type Sha1) Bytes() ([]byte, error) {

	if len(sha1Type.value) == 0 {
		return []byte{0x00}, nil
	}

	var res []byte
	b := sha1Type.value
	pushDataPrefix, err := bscript.PushDataPrefix(b)
	if err != nil {
		return res, err
	}

	return append(pushDataPrefix, b...), nil
}

func (sha1 Sha1) GetTypeString() string {
	return "Sha1"
}

func (sha1Type Sha1) MarshalJSON() ([]byte, error) {
	b := sha1Type.value
	l := fmt.Sprintf("\"Sha1(b'%s')\"", hex.EncodeToString(b))
	return []byte(l), nil
}

type Sha256 struct {
	// TODO: Should value be fixed size byte array instead?
	value []byte
}

func NewSha256(val []byte) Sha256 {
	return Sha256{val}
}

func (sha256Type Sha256) Hex() (string, error) {
	b, err := sha256Type.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (sha256Type Sha256) Bytes() ([]byte, error) {

	if len(sha256Type.value) == 0 {
		return []byte{0x00}, nil
	}

	var res []byte
	b := sha256Type.value
	pushDataPrefix, err := bscript.PushDataPrefix(b)
	if err != nil {
		return res, err
	}

	return append(pushDataPrefix, b...), nil
}

func (sha256 Sha256) GetTypeString() string {
	return "Sha256"
}

func (sha256Type Sha256) MarshalJSON() ([]byte, error) {
	b := sha256Type.value
	l := fmt.Sprintf("\"Sha256(b'%s')\"", hex.EncodeToString(b))
	return []byte(l), nil
}

type SigHashType struct {
	value []byte
}

func NewSighHashType(val []byte) SigHashType {
	return SigHashType{val}
}

func (sigHashType SigHashType) Hex() (string, error) {
	b, err := sigHashType.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (sigHashType SigHashType) Bytes() ([]byte, error) {

	if len(sigHashType.value) == 0 {
		return []byte{0x00}, nil
	}

	var res []byte
	b := sigHashType.value
	pushDataPrefix, err := bscript.PushDataPrefix(b)
	if err != nil {
		return res, err
	}

	return append(pushDataPrefix, b...), nil
}

func (sigHashType SigHashType) GetTypeString() string {
	return "SigHashType"
}

func (sigHashType SigHashType) MarshalJSON() ([]byte, error) {
	b := sigHashType.value
	l := fmt.Sprintf("\"SigHashType(b'%s')\"", hex.EncodeToString(b))
	return []byte(l), nil
}

type SigHashPreimage struct {
	value []byte
}

func NewSigHashPreimage(val []byte) SigHashPreimage {
	return SigHashPreimage{val}
}

func (sigHashPreimageType SigHashPreimage) Hex() (string, error) {
	b, err := sigHashPreimageType.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (sigHashPreimageType SigHashPreimage) Bytes() ([]byte, error) {

	if len(sigHashPreimageType.value) == 0 {
		return []byte{0x00}, nil
	}

	var res []byte
	b := sigHashPreimageType.value
	pushDataPrefix, err := bscript.PushDataPrefix(b)
	if err != nil {
		return res, err
	}

	return append(pushDataPrefix, b...), nil
}

func (sigHashPreimage SigHashPreimage) GetTypeString() string {
	return "SigHashPreimage"
}

func (sigHashPreimage SigHashPreimage) MarshalJSON() ([]byte, error) {
	b := sigHashPreimage.value
	l := fmt.Sprintf("\"SigHashPreimage(b'%s')\"", hex.EncodeToString(b))
	return []byte(l), nil
}

type OpCodeType struct {
	value []byte
}

func NewOpCodeType(val []byte) OpCodeType {
	return OpCodeType{val}
}

func (opCodeType OpCodeType) Hex() (string, error) {
	b, err := opCodeType.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (opCodeType OpCodeType) Bytes() ([]byte, error) {

	if len(opCodeType.value) == 0 {
		return []byte{0x00}, nil
	}

	var res []byte
	b := opCodeType.value
	pushDataPrefix, err := bscript.PushDataPrefix(b)
	if err != nil {
		return res, err
	}

	return append(pushDataPrefix, b...), nil
}

func (opCodeType OpCodeType) GetTypeString() string {
	return "OpCodeType"
}

func (opCodeType OpCodeType) MarshalJSON() ([]byte, error) {
	b := opCodeType.value
	l := fmt.Sprintf("\"OpCodeType(b'%s')\"", hex.EncodeToString(b))
	return []byte(l), nil
}

type Array struct {
	values []ScryptType
}

func NewArray(val []ScryptType) Array {
	return Array{val}
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

func (arrayType Array) Bytes() ([]byte, error) {
	var res []byte
	var buff bytes.Buffer
	for _, elem := range arrayType.values {
		b, err := elem.Bytes()
		if err != nil {
			return res, err
		}
		buff.Write(b)
	}
	return buff.Bytes(), nil
}

func (arrayType Array) GetTypeString() string {
	thisSize := len(arrayType.values)
	if thisSize > 0 {
		elemTypeString := arrayType.values[0].GetTypeString()

		if IsArrayType(elemTypeString) {
			// Split type string and lengths and add this arrays lengths at the beginning.
			tokens := strings.SplitN(elemTypeString, "[", 2)
			return fmt.Sprintf("%s[%d][%s", tokens[0], thisSize, tokens[1])
		} else {
			return fmt.Sprintf("%s[%d]", elemTypeString, thisSize)
		}
	}
	return ""
}

func (arr Array) MarshalJSON() ([]byte, error) {
	return json.Marshal(arr.values)
}

type GenericType struct {
	Generic string
	Actual  string
}

type Struct struct {
	typeName     string
	keysInOrder  []string
	values       map[string]ScryptType
	genericTypes []GenericType
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

func (structType Struct) Bytes() ([]byte, error) {
	var res []byte
	var buff bytes.Buffer
	for _, key := range structType.keysInOrder {
		elem := structType.values[key]
		b, err := elem.Bytes()
		if err != nil {
			return res, err
		}
		buff.Write(b)
	}
	return buff.Bytes(), nil
}

func (structType *Struct) UpdateValue(fieldName string, newVal ScryptType) error {
	newVals := make(map[string]ScryptType)
	for key, val := range structType.values {
		if key == fieldName {
			if newVal.GetTypeString() != val.GetTypeString() {
				return fmt.Errorf("type of field %s should be %s, but got %s", fieldName, val.GetTypeString(), newVal.GetTypeString())
			}
			newVals[key] = newVal
		} else {
			newVals[key] = val
		}
	}
	structType.values = newVals

	return nil
}

func (structType Struct) GetTypeString() string {

	if len(structType.genericTypes) == 0 {
		return structType.typeName
	}

	ts := make([]string, 0)
	for _, val := range structType.genericTypes {
		ts = append(ts, val.Actual)
	}

	return fmt.Sprintf("%s<%s>", structType.typeName, strings.Join(ts, ","))
}

func (structType Struct) MarshalJSON() ([]byte, error) {

	m := make(map[string]ScryptType)
	for _, key := range structType.keysInOrder {
		m[key] = structType.values[key]
	}
	return json.Marshal(m)
}

// TODO: Function for creating structs

type Library struct {
	typeName            string
	paramKeysInOrder    []string
	params              map[string]ScryptType
	propertyKeysInOrder []string
	properties          map[string]ScryptType
	genericTypes        []GenericType
}

func (libraryType Library) ctor() bool {
	for _, key := range libraryType.paramKeysInOrder {
		if strings.HasPrefix(key, "ctor.") {
			return true
		}
	}
	return false
}

func (libraryType Library) Hex() (string, error) {
	var b strings.Builder
	for _, key := range libraryType.paramKeysInOrder {
		elem := libraryType.params[key]
		hex, err := elem.Hex()
		if err != nil {
			return "", err
		}
		b.WriteString(hex)
	}
	return b.String(), nil
}

func (libraryType Library) Bytes() ([]byte, error) {
	var res []byte
	var buff bytes.Buffer
	for _, key := range libraryType.paramKeysInOrder {
		elem := libraryType.params[key]
		b, err := elem.Bytes()
		if err != nil {
			return res, err
		}
		buff.Write(b)
	}
	return buff.Bytes(), nil
}

func (libraryType *Library) UpdateValue(paramName string, newVal ScryptType) {
	// TODO: Is there a more efficient way to do value updates?

	if libraryType.ctor() {
		paramName = "ctor." + paramName
	}
	newParams := make(map[string]ScryptType)
	for key, val := range libraryType.params {
		if key == paramName {
			newParams[key] = newVal
		} else {
			newParams[key] = val
		}
	}
	libraryType.params = newParams
}

func (libraryType *Library) UpdatePropertyValue(propertyName string, newVal ScryptType) {
	// TODO: Is there a more efficient way to do value updates?
	newProperties := make(map[string]ScryptType)
	for key, val := range libraryType.properties {
		if key == propertyName {
			newProperties[key] = newVal
		} else {
			newProperties[key] = val
		}
	}
	libraryType.properties = newProperties
}

func (libraryType Library) GetTypeString() string {

	if len(libraryType.genericTypes) == 0 {
		return libraryType.typeName
	}

	ts := make([]string, 0)
	for _, val := range libraryType.genericTypes {
		ts = append(ts, val.Actual)
	}

	return fmt.Sprintf("%s<%s>", libraryType.typeName, strings.Join(ts, ","))
}

func (libraryType Library) MarshalJSON() ([]byte, error) {
	a := make([]ScryptType, 0)
	for _, key := range libraryType.paramKeysInOrder {
		a = append(a, libraryType.params[key])
	}
	return json.Marshal(a)
}

type HashedMap struct {
	values map[[32]byte][32]byte
}

func (hashedMapType HashedMap) GetTypeString() string {
	return "HashedMap"
}

func (hashedMapType *HashedMap) Set(key ScryptType, val ScryptType) error {
	hashKey, err := FlattenSHA256(key)
	if err != nil {
		return err
	}
	hashVal, err := FlattenSHA256(val)
	if err != nil {
		return err
	}
	hashedMapType.values[hashKey] = hashVal

	return nil
}

func (hashedMapType *HashedMap) Delete(key ScryptType) error {
	hashKey, err := FlattenSHA256(key)
	if err != nil {
		return err
	}

	_, ok := hashedMapType.values[hashKey]

	if !ok {
		return fmt.Errorf("key not present in HashedMap: \"%s\"", hashKey)
	}

	delete(hashedMapType.values, hashKey)

	return nil
}

func (hashedMapType HashedMap) KeyIndex(key ScryptType) (int64, error) {
	hashKey, err := FlattenSHA256(key)
	if err != nil {
		return -1, err
	}

	keysSorted := hashedMapType.GetKeysSorted()

	idx := 0
	for _, k := range keysSorted {
		if k == hashKey {
			return int64(idx), nil
		}
		idx++
	}

	return -1, fmt.Errorf("key not present in HashedMap: \"%s\"", hashKey)
}

func (hashedMapType HashedMap) GetKeysSorted() [][32]byte {
	keysAll := make([][32]byte, len(hashedMapType.values))
	i := 0
	for k := range hashedMapType.values {
		keysAll[i] = k
		i++
	}

	sort.SliceStable(keysAll,
		func(i, j int) bool {
			a := NumberFromBuffer(keysAll[i][:], true)
			b := NumberFromBuffer(keysAll[j][:], true)
			return a.Cmp(b) < 0
		})

	return keysAll
}

func (hashedMapType HashedMap) Hex() (string, error) {
	b, err := hashedMapType.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (hashedMapType HashedMap) RawHex() (string, error) {
	if len(hashedMapType.values) == 0 {
		return "", nil
	}

	b, err := hashedMapType.RawBytes()

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func (hashedMapType HashedMap) RawBytes() ([]byte, error) {
	if len(hashedMapType.values) == 0 {
		return []byte{}, nil
	}

	b, err := hashedMapType.Bytes()

	if err != nil {
		return b, err
	}

	return DropLenPrefix(b)
}

func (hashedMapType HashedMap) Bytes() ([]byte, error) {

	if len(hashedMapType.values) == 0 {
		return []byte{0x00}, nil
	}
	var buff bytes.Buffer

	keysSorted := hashedMapType.GetKeysSorted()
	for _, k := range keysSorted {
		val := hashedMapType.values[k]
		buff.Write(k[:])
		buff.Write(val[:])
	}

	buf := buff.Bytes()

	b, err := appendPushdataPrefix(buf)
	if err != nil {
		return b, err
	}

	return b, nil
}

func (hashedMapType HashedMap) MarshalJSON() ([]byte, error) {

	var buff bytes.Buffer

	keysSorted := hashedMapType.GetKeysSorted()
	for _, k := range keysSorted {
		val := hashedMapType.values[k]
		buff.Write(k[:])
		buff.Write(val[:])
	}

	b := buff.Bytes()

	if len(b) == 0 {
		return []byte("[\"b''\"]"), nil
	}

	l := fmt.Sprintf("[\"b'%s'\"]", hex.EncodeToString(b))
	return []byte(l), nil
}

func NewHashedMap() HashedMap {
	return HashedMap{
		values: make(map[[32]byte][32]byte),
	}
}

type HashedSet struct {
	values map[[32]byte]bool
}

func (hashedSetType HashedSet) GetTypeString() string {
	return "HashedSet"
}

func (hashedSetType *HashedSet) Add(key ScryptType) error {
	hashKey, err := FlattenSHA256(key)
	if err != nil {
		return err
	}
	hashedSetType.values[hashKey] = true

	return nil
}

func (hashedSetType *HashedSet) Delete(key ScryptType) error {
	hashKey, err := FlattenSHA256(key)
	if err != nil {
		return err
	}
	delete(hashedSetType.values, hashKey)

	return nil
}

func (hashedSetType HashedSet) KeyIndex(key ScryptType) (int64, error) {
	hashKey, err := FlattenSHA256(key)
	if err != nil {
		return -1, err
	}

	keysSorted := hashedSetType.GetKeysSorted()

	idx := 0
	for _, k := range keysSorted {
		if k == hashKey {
			return int64(idx), nil
		}
		idx++
	}

	return -1, errors.New(fmt.Sprintf("Key not present in HashedMap: \"%s\"", hashKey))
}

func (hashedSetType HashedSet) GetKeysSorted() [][32]byte {
	keysAll := make([][32]byte, len(hashedSetType.values))
	i := 0
	for k := range hashedSetType.values {
		keysAll[i] = k
		i++
	}

	sort.SliceStable(keysAll,
		func(i, j int) bool {
			a := NumberFromBuffer(keysAll[i][:], true)
			b := NumberFromBuffer(keysAll[j][:], true)
			return a.Cmp(b) < 0
		})

	return keysAll
}

func (hashedSetType HashedSet) Hex() (string, error) {
	b, err := hashedSetType.Bytes()
	if err != nil {
		return "", err
	}
	return EvenHexStr(fmt.Sprintf("%x", b)), nil
}

func (hashedSetType HashedSet) Bytes() ([]byte, error) {

	if len(hashedSetType.values) == 0 {
		return []byte{0x00}, nil
	}

	var buff bytes.Buffer

	keysSorted := hashedSetType.GetKeysSorted()
	for _, k := range keysSorted {
		buff.Write(k[:])
	}

	buf := buff.Bytes()

	b, err := appendPushdataPrefix(buf)
	if err != nil {
		return b, err
	}

	return b, nil
}

func (hashedSetType HashedSet) RawBytes() ([]byte, error) {
	if len(hashedSetType.values) == 0 {
		return []byte{}, nil
	}

	b, err := hashedSetType.Bytes()

	if err != nil {
		return b, err
	}

	return DropLenPrefix(b)
}

func (hashedSetType HashedSet) RawHex() (string, error) {
	if len(hashedSetType.values) == 0 {
		return "", nil
	}

	b, err := hashedSetType.RawBytes()

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func (hashedSetType HashedSet) MarshalJSON() ([]byte, error) {
	var buff bytes.Buffer

	keysSorted := hashedSetType.GetKeysSorted()
	for _, k := range keysSorted {
		buff.Write(k[:])
	}

	b := buff.Bytes()

	if len(b) == 0 {
		return []byte("[\"b''\"]"), nil
	}

	l := fmt.Sprintf("[\"b'%s'\"]", hex.EncodeToString(b))
	return []byte(l), nil
}

func NewHashedSet() HashedSet {
	return HashedSet{
		values: make(map[[32]byte]bool),
	}
}
