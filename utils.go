package scryptlib

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/libsv/go-bt/v2/bscript"
)

// Factor array declaration string to array type and sizes.
// e.g. 'int[N][N][4]' -> ('int', ['N', 'N', '4'])
func FactorizeArrayTypeString(typeStr string) (string, []string) {
	var arraySizes []string

	r := regexp.MustCompile(`\[([\w.]+)\]+`)
	matches := r.FindAllStringSubmatch(typeStr, -1)
	for _, match := range matches {
		arraySizes = append(arraySizes, match[1])
	}

	typeName := strings.Split(typeStr, "[")[0]

	return typeName, arraySizes
}

// Retruns array declaration string for given type name and sizes.
// Array sizes are passed as a slice of type []string.
func ToLiteralArrayTypeStr(typeName string, arraySizes []string) string {
	var resBuff strings.Builder
	resBuff.WriteString(typeName)
	for _, size := range arraySizes {
		resBuff.WriteRune('[')
		resBuff.WriteString(size)
		resBuff.WriteRune(']')
	}
	return resBuff.String()
}

// Retruns array declaration string for given type name and sizes.
// Array sizes are passed as a slice of type []int.
// TODO: Change int types to *big.Int
func ToLiteralArrayTypeInt(typeName string, arraySizes []int) string {
	var resBuff strings.Builder
	resBuff.WriteString(typeName)
	for _, size := range arraySizes {
		resBuff.WriteString(strconv.Itoa(size))
	}
	return resBuff.String()
}

// Check if string is of an array type.
// e.g. "int[2]" or "int[N][3]"
func IsArrayType(typeStr string) bool {
	match, _ := regexp.MatchString(`^(.+)(\[[\w.]+\])+$`, typeStr)
	return match
}

// Check if string is of a struct type.
// e.g. "struct Point {}"
//func IsStructType(typeStr string) bool {
//	match, _ := regexp.MatchString(`^struct\s(\w+)\s\{\}$`, typeStr)
//	return match
//}

// Check if string is a basic sCrypt type.
// e.g. "int", "bool", "bytes" ...
func IsBasicScryptType(typeStr string) bool {
	_, res := BASIC_SCRYPT_TYPES[typeStr]
	return res
}

// Returns struct name from type string.
// e.g.: 'struct ST1 {}[2][2][2]' -> 'ST1'.
//func GetStructNameByType(typeName string) string {
//	r := regexp.MustCompile(`^struct\s(\w+)\s\{\}.*$`)
//	match := r.FindStringSubmatch(typeName)
//	if match != nil {
//		return match[1]
//	}
//	return ""
//}

func ResolveType(typeStr string, aliases map[string]string) string {
	if IsArrayType(typeStr) {
		typeName, arraySizes := FactorizeArrayTypeString(typeStr)
		return ToLiteralArrayTypeStr(ResolveType(typeName, aliases), arraySizes)
	}

	resolvedType, ok := aliases[typeStr]
	if ok {
		return ResolveType(resolvedType, aliases)
	}

	return typeStr
}

func EvenHexStr(hexStr string) string {
	if len(hexStr)%2 == 1 {
		return "0" + hexStr
	}
	return hexStr
}

func BigIntToHex_LE(value *big.Int) string {
	b := BigIntToBytes_LE(value)
	return EvenHexStr(fmt.Sprintf("%x", b))
}

func BigIntToBytes_LE(value *big.Int) []byte {
	b := value.Bytes()
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	return b
}

// Returns true if the passed Struct sCrypt types are of the same structure.
// Concrete values are not checked! It only recursively goes through Array and Struct types.
func IsStructsSameStructure(struct0 Struct, struct1 Struct) bool {
	if len(struct0.keysInOrder) != len(struct1.keysInOrder) {
		return false
	}
	if len(struct0.values) != len(struct1.values) {
		return false
	}

	for i, key := range struct0.keysInOrder {
		// Check key order.
		if struct1.keysInOrder[i] != key {
			return false
		}

		// Check values.
		type0 := reflect.TypeOf(struct0.values[key]).Name()
		type1 := reflect.TypeOf(struct1.values[key]).Name()
		if type0 != type1 {
			return false
		}

		// Go deeper if struct or array type.
		if type0 == "Struct" {
			return IsStructsSameStructure(struct0.values[key].(Struct), struct1.values[key].(Struct))
		}
		if type0 == "Array" {
			return IsArraySameStructure(struct0.values[key].(Array), struct1.values[key].(Array))
		}

	}

	return true
}

// Returns true if the passed Library sCrypt types are of the same structure.
// Concrete values are not checked! It only recursively goes through Array , Library, Struct types.
func IsLibrarySameStructure(lib0 Library, lib1 Library) bool {
	if len(lib0.paramKeysInOrder) != len(lib1.paramKeysInOrder) {
		return false
	}
	if len(lib0.params) != len(lib1.params) {
		return false
	}

	for i, key := range lib0.paramKeysInOrder {
		// Check key order.
		if lib1.paramKeysInOrder[i] != key {
			return false
		}

		// Check values.
		type0 := reflect.TypeOf(lib0.params[key]).Name()
		type1 := reflect.TypeOf(lib1.params[key]).Name()
		if type0 != type1 {
			return false
		}

		// Go deeper if struct or array type.
		if type0 == "Struct" {
			return IsStructsSameStructure(lib0.params[key].(Struct), lib1.params[key].(Struct))
		} else if type0 == "Library" {
			return IsLibrarySameStructure(lib0.params[key].(Library), lib1.params[key].(Library))
		} else if type0 == "Array" {
			return IsArraySameStructure(lib1.params[key].(Array), lib1.params[key].(Array))
		}
	}

	if len(lib0.propertyKeysInOrder) != len(lib1.propertyKeysInOrder) {
		return false
	}
	if len(lib0.properties) != len(lib1.properties) {
		return false
	}

	for i, key := range lib0.propertyKeysInOrder {
		// Check key order.
		if lib1.propertyKeysInOrder[i] != key {
			return false
		}

		// Check values.
		type0 := reflect.TypeOf(lib0.properties[key]).Name()
		type1 := reflect.TypeOf(lib1.properties[key]).Name()
		if type0 != type1 {
			return false
		}

		// Go deeper if struct or array type.
		if type0 == "Struct" {
			return IsStructsSameStructure(lib0.properties[key].(Struct), lib1.properties[key].(Struct))
		} else if type0 == "Library" {
			return IsLibrarySameStructure(lib0.properties[key].(Library), lib1.properties[key].(Library))
		} else if type0 == "Array" {
			return IsArraySameStructure(lib1.properties[key].(Array), lib1.properties[key].(Array))
		}
	}

	return true
}

// Returns true if the passed Array sCrypt types are of the same structure.
// Concrete values are not checked! It only recursively goes through Array and Struct types.
func IsArraySameStructure(array0 Array, array1 Array) bool {
	if len(array0.values) != len(array1.values) {
		return false
	}

	for i, elem0 := range array0.values {
		elem1 := array1.values[i]

		// Check values.
		type0 := reflect.TypeOf(elem0).Name()
		type1 := reflect.TypeOf(elem1).Name()
		if type0 != type1 {
			return false
		}

		// Go deeper if struct or array type.
		if type0 == "Struct" {
			return IsStructsSameStructure(elem0.(Struct), elem1.(Struct))
		}
		if type0 == "Array" {
			return IsArraySameStructure(elem0.(Array), elem1.(Array))
		}
	}

	return true
}

// Construct a map for resolving alias types from the alias section of the contract description file.
func ConstructAliasMap(aliasesDesc []AliasEntity) map[string]string {
	aliases := make(map[string]string)
	for _, item := range aliasesDesc {
		nameString := item.Name
		typeString := item.Type
		aliases[nameString] = typeString
	}
	return aliases
}

func CompareScryptVariableTypes(a ScryptType, b ScryptType) bool {
	typePlaceholder := reflect.TypeOf(a).Name()
	typeActualParam := reflect.TypeOf(b).Name()

	return typePlaceholder == typeActualParam
}

func CompareScryptTypeSHA256(a ScryptType, b ScryptType) (bool, error) {
	hash_a, err := FlattenSHA256(a)
	if err != nil {
		return false, err
	}
	hash_b, err := FlattenSHA256(b)
	if err != nil {
		return false, err
	}
	return hash_a == hash_b, nil
}

func FlattenArray(arr Array) []ScryptType {
	res := make([]ScryptType, 0)

	if len(arr.values) == 0 {
		return res
	}

	areSubElemsArrays := IsArrayType(arr.values[0].GetTypeString())

	if areSubElemsArrays {
		for _, elem := range arr.values {
			res = append(res, FlattenArray(elem.(Array))...)
		}
	} else {
		res = append(res, arr.values...)
	}

	return res
}

func reSubMatchMap(r *regexp.Regexp, str string) map[string]string {
	match := r.FindStringSubmatch(str)
	subMatchMap := make(map[string]string)
	for i, name := range r.SubexpNames() {
		if i != 0 {
			subMatchMap[name] = match[i]
		}
	}

	return subMatchMap
}

func reSubMatchMapAll(r *regexp.Regexp, str string) []map[string]string {
	var res []map[string]string

	matches := r.FindAllStringSubmatch(str, -1)
	for _, match := range matches {
		subMatchMap := make(map[string]string)
		for i, name := range r.SubexpNames() {
			if i != 0 {
				subMatchMap[name] = match[i]
			}
		}
		res = append(res, subMatchMap)
	}

	return res
}

func appendPushdataPrefix(buffer []byte) ([]byte, error) {
	var res []byte

	pushDataPrefix, err := bscript.PushDataPrefix(buffer)
	if err != nil {
		return res, err
	}

	return append(pushDataPrefix, buffer...), nil
}

// Drops length prefix of serialized sCrypt type.
func DropLenPrefix(val []byte) ([]byte, error) {
	if len(val) < 2 {
		return val, nil
	}

	firstByte := val[0]

	if firstByte >= 0x01 && firstByte <= 0x4b {
		return val[1:], nil
	}

	if firstByte == 0x4c {
		// OP_PUSHDATA1
		return val[2:], nil
	} else if firstByte == 0x4d {
		// OP_PUSHDATA2
		return val[3:], nil
	} else if firstByte == 0x4e {
		// OP_PUSHDATA4
		return val[5:], nil
	}

	return nil, errors.New(fmt.Sprintf("Invalid first byte \"%x\".", firstByte))
}

// If data is Struct or a list of ScryptTypes, then hash (SHA256) every element of the flattened structure, concat
// the resulting hashes and hash again into a single hash.
// If data is a basic sCrypt type, then hash it's byte value.
func FlattenSHA256(val ScryptType) ([32]byte, error) {
	var res [32]byte
	flattened := FlattenData(val)

	if len(flattened) == 1 {
		valBytes, err := val.StateBytes()
		if err != nil {
			return res, err
		}
		valBytes, err = DropLenPrefix(valBytes)
		if err != nil {
			return res, err
		}
		if len(valBytes) == 1 && valBytes[0] == 0 {
			valBytes = make([]byte, 0)
		}
		return sha256.Sum256(valBytes), nil
	}

	var hashesBuff bytes.Buffer
	for _, e := range flattened {
		valBytes, err := e.Bytes()
		if err != nil {
			return res, err
		}
		if len(valBytes) == 1 && valBytes[0] == 0 {
			valBytes = make([]byte, 0)
		}
		valHash := sha256.Sum256(valBytes)
		hashesBuff.Write(valHash[:])
	}

	return sha256.Sum256(hashesBuff.Bytes()), nil
}

// Turns hierarchical sCrypt type into a single dimensional slice of ScryptType values.
func FlattenData(val ScryptType) []ScryptType {
	valType := reflect.TypeOf(val).Name()
	res := make([]ScryptType, 0)
	if valType == "Array" {
		for _, e := range val.(Array).values {
			res = append(res, FlattenData(e)...)
		}
	} else if valType == "Struct" {
		for _, k := range val.(Struct).keysInOrder {
			res = append(res, FlattenData(val.(Struct).values[k])...)
		}
	} else {
		res = append(res, val)
	}

	return res
}

func ReverseByteSlice(s []byte) []byte {
	a := make([]byte, len(s))
	copy(a, s)

	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}

	return a
}
