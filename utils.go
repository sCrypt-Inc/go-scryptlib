package scryptlib

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/sCrypt-Inc/go-bt/v2/bscript"
	"github.com/thoas/go-funk"
)

// Factor array declaration string to array type and sizes.
// e.g. 'int[N][N][4]' -> ('int', ['N', 'N', '4'])
func FactorizeArrayTypeString(typeStr string) (string, []string) {
	var arraySizes []string

	typeName := strings.Split(typeStr, "[")[0]

	sizeParts := typeStr[strings.Index(typeStr, "["):]

	if strings.Contains(typeStr, ">") {
		typeName = typeStr[0 : strings.LastIndex(typeStr, ">")+1]
		sizeParts = typeStr[strings.LastIndex(typeStr, ">")+1:]
	}

	r := regexp.MustCompile(`\[([\w.]+)\]+`)
	matches := r.FindAllStringSubmatch(sizeParts, -1)
	for _, match := range matches {
		arraySizes = append(arraySizes, match[1])
	}

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

// Check if string is a basic sCrypt type.
// e.g. "int", "bool", "bytes" ...
func IsBasicScryptType(typeStr string) bool {
	_, res := BASIC_SCRYPT_TYPES[typeStr]
	return res
}

func ResolveType(typeStr string, aliases map[string]string) string {
	if IsArrayType(typeStr) {
		typeName, arraySizes := FactorizeArrayTypeString(typeStr)
		return ToLiteralArrayTypeStr(ResolveType(typeName, aliases), arraySizes)
	}

	if IsGenericType(typeStr) {
		name, actualTypes := ParseGenericType(typeStr)

		n := ResolveType(name, aliases)

		gts := funk.Map(actualTypes, func(actualType string) string {
			return ResolveType(actualType, aliases)
		}).([]string)

		return fmt.Sprintf("%s<%s>", n, strings.Join(gts, ","))
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

	if value.Cmp(big.NewInt(0)) == -1 {
		// reset sign bit
		lastByte := b[len(b)-1]
		lastByte = lastByte | 0x80
		b[len(b)-1] = lastByte
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

	aliases["PubKeyHash"] = "Ripemd160"

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
		valBytes, err := e.StateBytes()
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

func NumberFromBuffer(s []byte, littleEndian bool) *big.Int {

	a := new(big.Int)

	if littleEndian {
		s = ReverseByteSlice(s)
	}

	if s[0]&0x80 == 0x80 {
		s[0] = s[0] & 0x7f
		b := new(big.Int)
		b.SetBytes(s)
		a.Neg(b)
	} else {
		a.SetBytes(s)
	}

	return a
}

func num2bin(n Int, dataLen int) (string, error) {
	if n.value.Cmp(big.NewInt(0)) == 0 {
		return strings.Repeat("00", dataLen), nil
	}

	b := BigIntToBytes_LE(n.value)

	s := fmt.Sprintf("%02x", b)

	byteLen_ := len(b)
	if byteLen_ > dataLen {
		return "", fmt.Errorf("cannot fit in %d bytes", dataLen)
	}

	if byteLen_ == dataLen {
		return s, nil
	}

	paddingLen := dataLen - byteLen_
	lastByte := b[byteLen_-1:][0]
	rest := b[:byteLen_-1]

	if n.value.Cmp(big.NewInt(0)) == -1 {
		// reset sign bit
		lastByte = lastByte & 0x7F
	}

	b = append(rest, lastByte)

	padding := ""

	if n.value.Cmp(big.NewInt(0)) == 1 {
		padding = strings.Repeat("00", paddingLen)
	} else {
		padding = strings.Repeat("00", paddingLen-1) + "80"
	}

	return fmt.Sprintf("%02x", b) + padding, nil
}

const (
	STATE_LEN_2BYTES = 2
	STATE_LEN_3BYTES = 3
	STATE_LEN_4BYTES = 4
)

// serialize contract state into Script hex
func serializeState(state string, stateBytes int) (string, error) {

	if stateBytes <= 1 || stateBytes > 4 {
		return "", fmt.Errorf("invalid stateBytes")
	}

	if len(strings.TrimSpace(state)) == 0 {
		h := fmt.Sprintf("%02x", stateBytes)
		return h + strings.Repeat("00", stateBytes), nil
	}

	s, err := hex.DecodeString(state)
	if err != nil {
		return "", err
	}

	s, err = appendPushdataPrefix(s)
	if err != nil {
		return "", err
	}
	stateLen := len(s)

	// use fixed size to denote state len
	lenHex, err := num2bin(NewInt(int64(stateLen)), stateBytes)

	if err != nil {
		return "", err
	}

	h := fmt.Sprintf("%02x", stateBytes)
	return hex.EncodeToString(s) + h + lenHex, nil

}

func isStringEmpty(s string) bool {
	return len(strings.TrimSpace(s)) == 0
}

func buildContractState(props *[]StateProp, firstCall bool) (string, error) {
	var res string

	contractStateVersion := 0

	var sb strings.Builder

	if firstCall {
		sb.WriteString("01")
	} else {
		sb.WriteString("00")
	}

	for _, stateProp := range *props {

		stateHex, err := stateProp.Value.StateHex()

		if err != nil {
			return res, err
		}

		sb.WriteString(stateHex)
	}

	sbLen := uint32(sb.Len() / 2)
	if sbLen > 0 {
		b1, _ := num2bin(Int{big.NewInt(int64(sbLen))}, 4)
		b2, _ := num2bin(Int{big.NewInt(int64(contractStateVersion))}, 1)
		sb.WriteString(b1)
		sb.WriteString(b2)
	}

	return sb.String(), nil
}

func IsGenericType(t string) bool {
	match, _ := regexp.MatchString(`^([\w]+)<([\w,[\]\s<>]+)>$`, t)
	return match
}

func GetNameByType(t string) string {

	if IsArrayType(t) {
		typeName, _ := FactorizeArrayTypeString(t)
		return GetNameByType(typeName)
	}

	if IsGenericType(t) {
		tn, _ := ParseGenericType(t)
		return GetNameByType(tn)
	}

	return t
}

/**
 *
 * @param type eg. HashedMap<int,int>
 * @param eg. ["HashedMap", ["int", "int"]}] An array generic types returned by @getGenericDeclaration
 * @returns {"K": "int", "V": "int"}
 */
func ParseGenericType(t string) (string, []string) {

	if IsGenericType(t) {
		r := regexp.MustCompile(`([\w]+)<([\w,[\]<>\s]+)>$`)
		matches := r.FindAllStringSubmatch(t, -1)

		if len(matches) == 1 {
			ln := matches[0][1]
			realTypes := make([]string, 0)

			tail := matches[0][2]

			brackets := make([]string, 0)
			tmpType := ""

			for i := 0; i < len(tail); i++ {
				ch := fmt.Sprintf("%c", tail[i])

				if ch == "<" || ch == "[" {
					//push
					brackets = append(brackets, ch)
				} else if ch == ">" || ch == "]" {
					//pop
					brackets = brackets[0 : len(brackets)-1]
				} else if ch == "," {

					if len(brackets) == 0 {
						realTypes = append(realTypes, strings.TrimSpace(tmpType))
						tmpType = ""
						continue
					}
				}
				tmpType += ch
			}

			realTypes = append(realTypes, strings.TrimSpace(tmpType))
			return ln, realTypes
		}
	}

	panic(fmt.Errorf("%s is not generic type", t))
}

func DeduceGenericType(t string, genericTypes []string) (map[string]string, error) {

	if IsGenericType(t) {
		_, actualTypes := ParseGenericType(t)

		if len(actualTypes) != len(genericTypes) {
			return nil, fmt.Errorf("deduce generic type %s fail", t)
		}

		i := 0
		r := funk.Reduce(genericTypes, func(acc map[string]string, genericType string) map[string]string {
			acc[genericType] = actualTypes[i]
			i++
			return acc
		}, make(map[string]string))
		return r.(map[string]string), nil
	}

	return make(map[string]string), nil

}

func DeduceActualType(t string, genericTypes map[string]string) string {

	if IsGenericType(t) {
		name, gts := ParseGenericType(t)

		gts_ := funk.Map(gts, func(t string) string {

			at := DeduceActualType(t, genericTypes)

			return at
		}).([]string)

		return fmt.Sprintf("%s<%s>", name, strings.Join(gts_, ","))
	} else if IsArrayType(t) {
		name, arraySizes := FactorizeArrayTypeString(t)
		name_ := DeduceActualType(name, genericTypes)
		return ToLiteralArrayTypeStr(name_, arraySizes)
	}

	if funk.Contains(genericTypes, t) {
		return genericTypes[t]
	}

	return t
}

func LoadDesc(file string) (DescriptionFile, error) {

	var desc DescriptionFile
	bytes, err := ioutil.ReadFile(file)

	if err != nil {
		return desc, err
	}

	err = json.Unmarshal(bytes, &desc)

	if err != nil {
		return desc, err
	}

	return desc, nil
}
