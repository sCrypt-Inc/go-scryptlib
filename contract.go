package scryptlib

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/libsv/go-bt/v2"
	"github.com/libsv/go-bt/v2/bscript"
	"github.com/libsv/go-bt/v2/bscript/interpreter"
	"github.com/libsv/go-bt/v2/bscript/interpreter/scriptflag"
)

/*
The code below implements the Contract structure which represents a compiled sCrypt contract. Contract structs are created by parsing a contract description (desc).
TODO: Make parsing the contract description cleaner. In the current implementation there's a lot of repetition and parameter passing, which can be simplified).
*/

type functionParam struct {
	Name       string
	TypeString string
	Value      ScryptType
	IsState    bool
}

func (param *functionParam) setParamValue(value ScryptType) error {
	// TODO: TypeString should already be resolved so make sure the parameter values that get to here are too!
	if param.TypeString != value.GetTypeString() {
		errMsg := fmt.Sprintf("Passed item of type \"%s\" for parameter with name \"%s\". Expected \"%s\".",
			value.GetTypeString(), param.Name, param.TypeString)
		return errors.New(errMsg)
	}

	param.Value = value
	return nil
}

type publicFunction struct {
	FunctionName string
	Index        int
	Params       []functionParam // TODO: Maybe make this a map, because order is set by the hex template.
}

type ExecutionContext struct {
	Tx       *bt.Tx
	InputIdx int
	Flags    scriptflag.Flag
}

type Contract struct {
	lockingScriptHexTemplate string
	aliases                  map[string]string
	constructorParams        []functionParam
	publicFunctions          map[string]publicFunction
	structTypes              map[string]Struct // Templates of contracts struct types.
	// Maps struct names to related templates.
	libraryTypes     map[string]Library // Templates of contracts libraries.
	executionContext ExecutionContext
	contextSet       bool
}

// Set values for the contracts constructors parameters.
// The value of "params" must be a map, that maps a public function name (string) to an ScryptType object.
func (contract *Contract) SetConstructorParams(params map[string]ScryptType) error {
	if len(params) != len(contract.constructorParams) {
		errMsg := fmt.Sprintf("Passed %d parameter values to constructor, but %d expected.",
			len(params), len(contract.constructorParams))
		return errors.New(errMsg)
	}

	for idx := range contract.constructorParams {
		paramPlaceholder := &contract.constructorParams[idx]
		value := params[paramPlaceholder.Name]

		typePlaceholder := reflect.TypeOf(paramPlaceholder.Value).Name()
		typeActualParam := reflect.TypeOf(value).Name()

		if typePlaceholder != typeActualParam {
			errMsg := fmt.Sprintf("Passed value for param with name \"%s\" is not of the right type. Got \"%s\" but expected \"%s\"",
				paramPlaceholder.Name, typeActualParam, typeActualParam)
			return errors.New(errMsg)
		}

		if typePlaceholder == "Struct" {
			same := IsStructsSameStructure(paramPlaceholder.Value.(Struct), value.(Struct))
			if !same {
				errMsg := fmt.Sprintf("Passed Struct value for param with name \"%s\" is not of the right structure.",
					paramPlaceholder.Name)
				return errors.New(errMsg)
			}
		} else if typePlaceholder == "Array" {
			same := IsArraySameStructure(paramPlaceholder.Value.(Array), value.(Array))
			if !same {
				errMsg := fmt.Sprintf("Passed Array value for param with name \"%s\" is not of the right structure.",
					paramPlaceholder.Name)
				return errors.New(errMsg)
			}
		}

		err := paramPlaceholder.setParamValue(value)
		if err != nil {
			return err
		}
	}

	return nil
}

// Set values for a specific public function parameters.
// The value of "params" must be a map, that maps a public function name (string) to an ScryptType object.
func (contract *Contract) SetPublicFunctionParams(functionName string, params map[string]ScryptType) error {
	function := contract.publicFunctions[functionName]

	if len(params) != len(function.Params) {
		errMsg := fmt.Sprintf("Passed %d parameter values to function \"%s\", but %d expected.",
			len(params), function.FunctionName, len(function.Params))
		return errors.New(errMsg)
	}

	for idx := range function.Params {
		paramPlaceholder := &function.Params[idx]
		value := params[paramPlaceholder.Name]

		typePlaceholder := reflect.TypeOf(paramPlaceholder.Value).Name()
		typeActualParam := reflect.TypeOf(value).Name()

		if typePlaceholder != typeActualParam {
			errMsg := fmt.Sprintf("Passed value for param with name \"%s\" is not of the right type. Got \"%s\" but expected \"%s\"",
				paramPlaceholder.Name, typeActualParam, typeActualParam)
			return errors.New(errMsg)
		}

		if typePlaceholder == "Struct" {
			same := IsStructsSameStructure(paramPlaceholder.Value.(Struct), value.(Struct))
			if !same {
				errMsg := fmt.Sprintf("Passed Struct value for param with name \"%s\" is not of the right structure.",
					paramPlaceholder.Name)
				return errors.New(errMsg)
			}
		} else if typePlaceholder == "Array" {
			same := IsArraySameStructure(paramPlaceholder.Value.(Array), value.(Array))
			if !same {
				errMsg := fmt.Sprintf("Passed Array value for param with name \"%s\" is not of the right structure.",
					paramPlaceholder.Name)
				return errors.New(errMsg)
			}
		}

		paramPlaceholder.setParamValue(value)
	}

	return nil
}

// Returns if the contracts execution context was already set at least once.
func (contract *Contract) IsExecutionContextSet() bool {
	return contract.contextSet
}

// Set the execution context, that will be used while evaluating a contracts public function.
// The locking and unlocking scripts, that you wan't to evaluate can be just templates, as they will be substitued localy,
// while calling the EvaluatePublicFunction method.
func (contract *Contract) SetExecutionContext(ec ExecutionContext) {
	contract.executionContext = ec
	contract.contextSet = true
}

// Evaluate a public function call locally and return whether the evaluation was successfull,
// meaning the public function call (unlocking script) successfully evaluated against the contract (lockingScript).
// Constructor parameter values and also the public function parameter values MUST be set.
func (contract *Contract) EvaluatePublicFunction(functionName string) (bool, error) {
	// TODO: Check if parameter vals haven't been set yet. Use flags.

	unlockingScript, err := contract.GetUnlockingScript(functionName)
	if err != nil {
		return false, err
	}

	if !contract.contextSet {
		lockingScript, err := contract.GetLockingScript()
		if err != nil {
			return false, err
		}
		err = interpreter.NewEngine().Execute(
			interpreter.WithScripts(lockingScript, unlockingScript),
			interpreter.WithAfterGenesis(),
		)

		if err != nil {
			return false, err
		}
	} else {
		contract.executionContext.Tx.Inputs[contract.executionContext.InputIdx].UnlockingScript = unlockingScript
		prevoutSats := contract.executionContext.Tx.InputIdx(contract.executionContext.InputIdx).PreviousTxSatoshis
		prevLockingScript := contract.executionContext.Tx.InputIdx(contract.executionContext.InputIdx).PreviousTxScript

		engine := interpreter.NewEngine()
		err = engine.Execute(
			interpreter.WithTx(
				contract.executionContext.Tx,
				contract.executionContext.InputIdx,
				&bt.Output{LockingScript: prevLockingScript, Satoshis: prevoutSats},
			),
			interpreter.WithFlags(
				contract.executionContext.Flags,
			),
			interpreter.WithAfterGenesis(),
		)
		if err != nil {
			return false, err
		}
	}

	return true, nil
}

func (contract *Contract) GetUnlockingScript(functionName string) (*bscript.Script, error) {
	var res *bscript.Script
	var sb strings.Builder

	publicFunction := contract.publicFunctions[functionName]

	for _, param := range publicFunction.Params {
		paramHex, err := param.Value.Hex()
		if err != nil {
			return res, err
		}
		sb.WriteString(paramHex)
	}

	// Append public function index.
	if len(contract.publicFunctions) > 1 {
		index := Int{big.NewInt(int64(publicFunction.Index))}
		indexHex, err := index.Hex()
		if err != nil {
			return res, err
		}
		sb.WriteString(indexHex)
	}

	unlockingScript, err := bscript.NewFromHexString(sb.String())
	if err != nil {
		return res, err
	}

	return unlockingScript, nil
}

func (contract *Contract) GetLockingScript() (*bscript.Script, error) {
	var res *bscript.Script

	codePart, err := contract.GetCodePart()
	if err != nil {
		return res, err
	}

	dataPart, err := contract.GetDataPart()
	if err != nil {
		return res, err
	}

	if dataPart != "" {
		// Code and data part are seperated by OP_RETURN.
		res, err = bscript.NewFromHexString(codePart + "6a" + dataPart)
	} else {
		res, err = bscript.NewFromHexString(codePart)
	}
	if err != nil {
		return res, err
	}

	return res, nil
}

func (contract *Contract) GetCodePart() (string, error) {
	// Get the code part of the locking script. This will contain contract opcodes and constructor parameters, that aren't statefull.
	// It also contains placeholders for statefull variables, that the script needs during evaluation. These always have the value 0x00.
	// The actual values of the statefull variables are in the data part of the locking script.

	// TODO: This whole function would probably be more efficient if we would iterate through each placeholder in the template
	//       and finding the appropriate param value, instead of deriving, searching and replacing them for each param itself.

	var res string
	var err error

	lockingScriptHex := contract.lockingScriptHexTemplate

	lockingScriptHex = strings.Replace(lockingScriptHex, "<__codePart__>", "00", 1)

	for _, param := range contract.constructorParams {
		lockingScriptHex, err = contract.substituteParamInTemplate(lockingScriptHex, param.Value, param.Name, param.IsState)
		if err != nil {
			return res, err
		}
	}

	return lockingScriptHex, nil
}

func (contract *Contract) GetDataPart() (string, error) {
	// Get the data part of the locking script. This will contain all the serialized values of statefull variables of the contract.
	// The data part gets appended to the end of the locking script, seperated by OP_RETURN (0x6a).

	var res string

	contractStateVersion := 0

	var sb strings.Builder
	for _, param := range contract.constructorParams {
		if !param.IsState {
			continue
		}

		paramHex, err := param.Value.StateHex()
		if err != nil {
			return res, err
		}

		sb.WriteString(paramHex)
	}

	sbLen := uint32(sb.Len() / 2)
	if sbLen > 0 {
		sizeLE := make([]byte, 4)
		binary.LittleEndian.PutUint32(sizeLE, sbLen)
		sb.WriteString(fmt.Sprintf("%x", sizeLE))

		sb.WriteString(fmt.Sprintf("%02x", contractStateVersion))
	}

	return sb.String(), nil
}

func (contract *Contract) UpdateStateVariable(variableName string, value ScryptType) error {
	// TODO: Make state variable lookup with a map instead of going through all constructor params.
	for i := range contract.constructorParams {
		param := &contract.constructorParams[i]

		if param.Name != variableName {
			continue
		}

		if !param.IsState {
			return errors.New(fmt.Sprintf("\"%s\" is not a state variable.", variableName))
		}

		if !CompareScryptVariableTypes(param.Value, value) {
			return errors.New(fmt.Sprintf("Variable \"%s\" value must be of type %T. Actual type is %T.", variableName, param.Value, value))
		}

		param.Value = value
		return nil
	}

	return errors.New(fmt.Sprintf("No variable named \"%s\".", variableName))
}

// Get templates of all struct types defined in the contract. Returns map with struct type names as keys and templates as values.
func (contract *Contract) GetStructTypeTemplates() map[string]Struct {
	res := make(map[string]Struct)
	for key, value := range contract.structTypes {
		res[key] = value
	}
	return res
}

// Returns template of a specific struct type defined in the contract.
func (contract *Contract) GetStructTypeTemplate(structName string) Struct {
	return contract.structTypes[structName]
}

func constructAbiPlaceholders(desc map[string]interface{},
	structItems map[string]Struct,
	libaryItems map[string]Library,
	aliases map[string]string) ([]functionParam, map[string]publicFunction, error) {
	var constructorParams []functionParam
	publicFunctions := make(map[string]publicFunction)

	// TODO: Pass this as a pram instead of recreating it here.
	structDescItemsByTypeString := getStructItemsByTypeString(desc)
	libraryDescItemsByTypeString := getLibraryItemsByTypeString(desc)

	for _, abiItem := range desc["abi"].([]ABIEntity) {

		abiItemType := abiItem.Type
		params := abiItem.Params

		var publicFunctionPlaceholder publicFunction
		var publicFunctionName string
		if abiItemType == FUNCTION {
			publicFunctionName = abiItem.Name
			publicFunctionPlaceholder = publicFunction{
				FunctionName: publicFunctionName,
				Index:        abiItem.Index,
			}
		}

		for _, param := range params {
			var value ScryptType
			pName := param.Name
			pType := param.Type

			structItem, isStructType := structItems[pType]
			libaryItem, isLibraryType := libaryItems[pType]

			if isStructType {
				value = structItem
			} else if isLibraryType {
				value = libaryItem
			} else if IsArrayType(pType) {
				arrVal, err := constructArrayType(pType, structDescItemsByTypeString, libraryDescItemsByTypeString, aliases)
				if err != nil {
					return nil, publicFunctions, err
				}
				value = arrVal
			} else {
				// Concrete values.
				val, err := createPrimitiveTypeWDefaultVal(pType)
				if err != nil {
					return nil, publicFunctions, err
				}
				value = val
			}

			placeholder := functionParam{
				Name:       pName,
				TypeString: pType,
				Value:      value,
			}

			if abiItemType == "constructor" {
				//TODO: now store isState in stateProps
				placeholder.IsState = false
				constructorParams = append(constructorParams, placeholder)
			} else {
				publicFunctionPlaceholder.Params = append(publicFunctionPlaceholder.Params, placeholder)
			}
		}

		if abiItemType == "function" {
			publicFunctions[publicFunctionName] = publicFunctionPlaceholder
		}
	}

	return constructorParams, publicFunctions, nil
}

func getStructItemsByTypeString(desc map[string]interface{}) map[string]StructEntity {
	res := make(map[string]StructEntity)
	for _, structItem := range desc["structs"].([]StructEntity) {
		structType := structItem.Name
		res[structType] = structItem
	}
	return res
}

func getLibraryItemsByTypeString(desc map[string]interface{}) map[string]LibraryEntity {
	res := make(map[string]LibraryEntity)
	for _, libraryItem := range desc["library"].([]LibraryEntity) {
		typeStr := libraryItem.Name
		res[typeStr] = libraryItem
	}
	return res
}

func getStructTypeNames(desc map[string]interface{}) map[string]bool {
	res := make(map[string]bool)
	for _, structItem := range desc["structs"].([]map[string]interface{}) {
		name := structItem["name"].(string)
		res[name] = true
	}
	return res
}

func getLibraryTypeNames(desc map[string]interface{}) map[string]bool {
	res := make(map[string]bool)
	for _, libraryItem := range desc["library"].([]map[string]interface{}) {
		name := libraryItem["name"].(string)
		res[name] = true
	}
	return res
}

func constructStructTypeItems(structDescItemsByTypeString map[string]StructEntity,
	aliases map[string]string) (map[string]Struct, error) {
	res := make(map[string]Struct)

	for typeName, typeItem := range structDescItemsByTypeString {
		typeItem, err := constructStructTypeItem(typeItem, structDescItemsByTypeString, aliases)

		if err != nil {
			return res, err
		}

		res[typeName] = typeItem
	}

	return res, nil
}

func constructLibraryTypeItems(structDescItemsByTypeString map[string]StructEntity,
	libraryDescItemsByTypeString map[string]LibraryEntity,
	aliases map[string]string) (map[string]Library, error) {
	res := make(map[string]Library)

	for typeName, typeItem := range libraryDescItemsByTypeString {
		typeItem, err := constructLibraryTypeItem(typeItem, structDescItemsByTypeString, libraryDescItemsByTypeString, aliases)
		if err != nil {
			return res, err
		}

		res[typeName] = typeItem
	}

	return res, nil
}

func constructStructTypeItem(typeDescItem StructEntity,
	structDescItemsByTypeString map[string]StructEntity,
	aliases map[string]string) (Struct, error) {

	var res Struct

	var keysInOrder []string
	values := make(map[string]ScryptType)

	params := typeDescItem.Params
	for _, param := range params {
		pName := param.Name
		pType := param.Type
		pTypeResolved := ResolveType(pType, aliases)

		keysInOrder = append(keysInOrder, pName)

		_, isParamStructType := structDescItemsByTypeString[pName]

		var val ScryptType
		var err error

		if IsArrayType(pTypeResolved) {
			emptyDescItemsByTypeString := make(map[string]LibraryEntity)
			val, err = constructArrayType(pTypeResolved, structDescItemsByTypeString, emptyDescItemsByTypeString, aliases)
		} else if isParamStructType {
			val, err = constructStructTypeItem(typeDescItem, structDescItemsByTypeString, aliases)
		} else {
			val, err = createPrimitiveTypeWDefaultVal(pTypeResolved)
		}

		if err != nil {
			return res, err
		}

		values[pName] = val
	}

	return Struct{
		typeName:    typeDescItem.Name,
		keysInOrder: keysInOrder,
		values:      values,
	}, nil
}

func constructLibraryTypeItem(typeDescItem LibraryEntity,
	structDescItemsByTypeString map[string]StructEntity,
	libraryDescItemsByTypeString map[string]LibraryEntity,
	aliases map[string]string) (Library, error) {

	var res Library

	var keysInOrder []string
	values := make(map[string]ScryptType)

	params := typeDescItem.Params
	for _, param := range params {
		pName := param.Name
		pType := param.Type
		pTypeResolved := ResolveType(pType, aliases)

		keysInOrder = append(keysInOrder, pName)

		structDescItem, isParamStructType := structDescItemsByTypeString[pName]
		libraryDescItem, isParamLibraryType := libraryDescItemsByTypeString[pName]

		var val ScryptType
		var err error

		if IsArrayType(pTypeResolved) {
			val, err = constructArrayType(pTypeResolved, structDescItemsByTypeString, libraryDescItemsByTypeString, aliases)
		} else if isParamStructType {
			val, err = constructStructTypeItem(structDescItem, structDescItemsByTypeString, aliases)
		} else if isParamLibraryType {
			val, err = constructLibraryTypeItem(libraryDescItem, structDescItemsByTypeString, libraryDescItemsByTypeString, aliases)
		} else {
			val, err = createPrimitiveTypeWDefaultVal(pTypeResolved)
		}

		if err != nil {
			return res, err
		}

		values[pName] = val
	}

	return Library{
		typeName:         typeDescItem.Name,
		paramKeysInOrder: keysInOrder,
		params:           values,
	}, nil
}

func constructArrayType(typeString string,
	structDescItemsByTypeString map[string]StructEntity,
	libraryDescItemsByTypeString map[string]LibraryEntity,
	aliases map[string]string) (Array, error) {

	var res Array
	typeName, arraySizes := FactorizeArrayTypeString(typeString)

	structDescItem, isStructType := structDescItemsByTypeString[typeName]
	libraryDescItem, isLibraryType := libraryDescItemsByTypeString[typeName]

	var items []ScryptType
	for dimension := len(arraySizes) - 1; dimension >= 0; dimension-- {
		arraySize := arraySizes[dimension]
		nItems, _ := strconv.Atoi(arraySize)

		if dimension == len(arraySizes)-1 {
			// Last dimension. Create concrete types here.
			for i := 0; i < nItems; i++ {
				var item ScryptType
				var err error

				if isStructType {
					item, err = constructStructTypeItem(structDescItem, structDescItemsByTypeString, aliases)
				} else if isLibraryType {
					item, err = constructLibraryTypeItem(libraryDescItem, structDescItemsByTypeString, libraryDescItemsByTypeString, aliases)
				} else {
					item, err = createPrimitiveTypeWDefaultVal(typeName)
				}

				if err != nil {
					return res, err
				}

				items = append(items, item)
			}
		} else {
			var itemsNewDimension []ScryptType
			for i := 0; i < nItems; i++ {
				// Copy items from level below.
				values := make([]ScryptType, len(items))
				copy(values, items)
				itemsNewDimension = append(itemsNewDimension, Array{values})
			}
			items = itemsNewDimension
		}
	}

	return Array{items}, nil
}

func createPrimitiveTypeWDefaultVal(typeString string) (ScryptType, error) {
	var res ScryptType
	switch typeString {
	case "bool":
		res = Bool{true}
	case "int":
		res = Int{big.NewInt(0)}
	case "bytes":
		res = Bytes{make([]byte, 0)}
	case "PrivKey":
		res = PrivKey{nil}
	case "PubKey":
		res = PubKey{nil}
	case "Sig":
		res = Sig{nil, 0}
	case "Ripemd160":
		res = Ripemd160{make([]byte, 0)}
	case "Sha1":
		res = Sha1{make([]byte, 0)}
	case "Sha256":
		res = Sha256{make([]byte, 0)}
	case "SigHashType":
		res = SigHashType{make([]byte, 0)}
	case "SigHashPreimage":
		res = SigHashPreimage{make([]byte, 0)}
	case "OpCodeType":
		res = OpCodeType{make([]byte, 0)}
	default:
		return res, errors.New(fmt.Sprintf("Unknown type string \"%s\".", typeString))
	}
	return res, nil
}

// Creates a new instance of Contract type from the contracts description tree.
func NewContractFromDesc(desc map[string]interface{}) (Contract, error) {
	var res Contract

	lockingScriptHexTemplate := desc["hex"].(string)
	aliases := ConstructAliasMap(desc["alias"].([]AliasEntity))

	structDescItemsByTypeString := getStructItemsByTypeString(desc)
	libraryDescItemsByTypeString := getLibraryItemsByTypeString(desc)

	structItems, err := constructStructTypeItems(structDescItemsByTypeString, aliases)
	if err != nil {
		return res, err
	}

	libaryItems, err := constructLibraryTypeItems(structDescItemsByTypeString, libraryDescItemsByTypeString, aliases)
	if err != nil {
		return res, err
	}

	// structTypes and libraryTypes should also contain keys for aliases.
	// TODO: Fix aliases for concrete vals.
	for key, val := range aliases {
		if _, contains := structItems[val]; contains {
			structItems[key] = structItems[val]
		}
	}
	for key, val := range aliases {
		if _, contains := libaryItems[val]; contains {
			libaryItems[key] = libaryItems[val]
		}
	}

	// Initialize constructor parameter placeholders and public functions along its parameter placeholders.
	constructorParams, publicFunctions, err := constructAbiPlaceholders(desc, structItems, libaryItems, aliases)
	if err != nil {
		return res, err
	}

	return Contract{
		lockingScriptHexTemplate: lockingScriptHexTemplate,
		aliases:                  aliases,
		constructorParams:        constructorParams,
		publicFunctions:          publicFunctions,
		structTypes:              structItems,
		libraryTypes:             libaryItems,
		contextSet:               false,
	}, nil
}

// Creates a new instance of Contract type.
func NewContract(compilerResult CompilerResult) (Contract, error) {
	var res Contract

	desc, err := compilerResult.ToDescWSourceMap()
	if err != nil {
		return res, err
	}

	res, err = NewContractFromDesc(desc)
	if err != nil {
		return res, err
	}

	return res, nil
}

func (contract *Contract) substituteParamInTemplate(lockingScriptHex string, elem ScryptType, paramName string, isState bool) (string, error) {
	typeStr := elem.GetTypeString()
	if IsBasicScryptType(typeStr) {
		// If this parameter is part of the contracts state, then we only have to substitute the placeholder with an arbitrary
		// value. This value gets replaced by the actual vale in the state part of the script during a contract call evaluation.
		elemHex := "00"
		if !isState {
			hexVal, err := elem.Hex()
			if err != nil {
				return "", err
			}
			elemHex = hexVal
		}
		toReplace := fmt.Sprintf("<%s>", paramName)
		return strings.Replace(lockingScriptHex, toReplace, elemHex, 1), nil
	} else if IsArrayType(typeStr) {
		arr := elem.(Array)
		return contract.substituteArrayParamInTemplate(lockingScriptHex, arr, paramName, isState)
	} else {
		structItem := elem.(Struct)
		return contract.substituteStructParamInTemplate(lockingScriptHex, structItem, paramName, isState)
	}
}

func (contract *Contract) substituteArrayParamInTemplate(lockingScriptHex string, arr Array, paramName string, isState bool) (string, error) {
	elems := FlattenArray(arr)
	elemTypeName, sizes := FactorizeArrayTypeString(arr.GetTypeString())
	areElemsBasicScryptTypes := IsBasicScryptType(elemTypeName)

	for i := 0; i < len(elems); i++ {
		elem := elems[i]

		indexes := make([]int, len(sizes))
		offsetMult := 1
		for j := len(sizes) - 1; j >= 0; j-- {
			size, err := strconv.Atoi(sizes[j])
			if err != nil {
				return "", err
			}

			offsetMult *= size
			indexes[j] = i % offsetMult
		}

		var sb strings.Builder
		for _, index := range indexes {
			sb.WriteString(fmt.Sprintf("[%d]", index))
		}
		toReplace := fmt.Sprintf("%s%s", paramName, sb.String())
		if areElemsBasicScryptTypes {
			elemHex, err := elem.Hex()
			if err != nil {
				return "", err
			}
			if isState {
				lockingScriptHex = strings.Replace(lockingScriptHex, "<"+toReplace+">", "00", 1)
			} else {
				lockingScriptHex = strings.Replace(lockingScriptHex, "<"+toReplace+">", elemHex, 1)
			}
		} else {
			// Structs.
			var err error
			lockingScriptHex, err = contract.substituteStructParamInTemplate(lockingScriptHex, elem.(Struct), toReplace, isState)
			if err != nil {
				return "", err
			}
		}
	}

	return lockingScriptHex, nil
}

func (contract *Contract) substituteStructParamInTemplate(lockingScriptHex string, structItem Struct, paramName string, isState bool) (string, error) {
	for _, key := range structItem.keysInOrder {
		toReplace := fmt.Sprintf("%s.%s", paramName, key)
		val := structItem.values[key]

		if IsArrayType(val.GetTypeString()) {
			res, err := contract.substituteArrayParamInTemplate(lockingScriptHex, val.(Array), toReplace, isState)
			if err != nil {
				return "", err
			}
			lockingScriptHex = res
		} else {
			if isState {
				lockingScriptHex = strings.Replace(lockingScriptHex, "<"+toReplace+">", "00", 1)
			} else {
				valHex, err := val.Hex()
				if err != nil {
					return "", err
				}
				lockingScriptHex = strings.Replace(lockingScriptHex, "<"+toReplace+">", valHex, 1)
			}
		}
	}

	return lockingScriptHex, nil
}
