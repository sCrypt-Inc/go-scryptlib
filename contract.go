package scryptlib

import (
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
	"github.com/thoas/go-funk"
)

/*
The code below implements the Contract structure which represents a compiled sCrypt contract. Contract structs are created by parsing a contract description (desc).
TODO: Make parsing the contract description cleaner. In the current implementation there's a lot of repetition and parameter passing, which can be simplified).
*/

type functionParam struct {
	Name       string
	TypeString string
	Value      ScryptType
}

type StateProp struct {
	Name       string
	TypeString string
	Value      ScryptType
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
	name                     string
	lockingScriptHexTemplate string
	executedPubFunc          string
	dataPartInASM            string
	dataPartInHex            string
	abis                     []ABIEntity
	constructorParams        []functionParam
	stateProps               []StateProp
	publicFunctions          map[string]publicFunction
	//structTypes              map[string]Struct // Templates of contracts struct types.
	// Maps struct names to related templates.
	//libraryTypes     map[string]Library // Templates of contracts libraries.
	typeItems        map[string]interface{}
	executionContext ExecutionContext
	file             string
	contextSet       bool
	firstCall        bool

	typeResolver func(string) string
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
		} else if typePlaceholder == "Library" {
			same := IsLibrarySameStructure(paramPlaceholder.Value.(Library), value.(Library))
			if !same {
				errMsg := fmt.Sprintf("Passed Library value for param with name \"%s\" is not of the right structure.",
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

		err := contract.checkParamValue(paramPlaceholder, value)

		if err != nil {
			return err
		}

		paramPlaceholder.Value = value
	}

	return nil
}

// Set values for a specific public function parameters.
// The value of "params" must be a map, that maps a public function name (string) to an ScryptType object.
func (contract *Contract) SetPublicFunctionParams(functionName string, params map[string]ScryptType) error {
	function, exist := contract.publicFunctions[functionName]

	if !exist {
		return fmt.Errorf("contract %s does't have function  \"%s\"", contract.name, functionName)
	}

	if len(params) != len(function.Params) {
		errMsg := fmt.Sprintf("Passed %d parameter values to function \"%s\", but %d expected.",
			len(params), function.FunctionName, len(function.Params))
		return errors.New(errMsg)
	}

	for idx := range function.Params {
		paramPlaceholder := &function.Params[idx]
		value, ok := params[paramPlaceholder.Name]
		if !ok {
			return fmt.Errorf("can not find parameter %s", paramPlaceholder.Name)
		}

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
		} else if typePlaceholder == "Library" {
			same := IsLibrarySameStructure(paramPlaceholder.Value.(Library), value.(Library))
			if !same {
				errMsg := fmt.Sprintf("Passed Library value for param with name \"%s\" is not of the right structure.",
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

		err := contract.checkParamValue(paramPlaceholder, value)

		if err != nil {
			return err
		}

		paramPlaceholder.Value = value
	}

	return nil
}

// Returns if the contracts execution context was already set at least once.
func (contract *Contract) checkParamValue(param *functionParam, value ScryptType) error {

	ExpectedType := contract.typeResolver(param.TypeString)
	ValueType := value.GetTypeString()
	if ExpectedType != ValueType {
		errMsg := fmt.Sprintf("Passed item of type \"%s\" for parameter with name \"%s\". Expected \"%s\".",
			ExpectedType, param.Name, ValueType)
		return errors.New(errMsg)
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

	contract.executedPubFunc = functionName

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
			url := contract.genLaunchConfig()
			fmt.Println(url)
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
			url := contract.genLaunchConfig()
			fmt.Println(url)
			return false, err
		}
	}

	return true, nil
}

func (contract *Contract) GetUnlockingScript(functionName string) (*bscript.Script, error) {
	var res *bscript.Script
	var sb strings.Builder

	publicFunction, exist := contract.publicFunctions[functionName]

	if !exist {
		return res, fmt.Errorf("contract %s does't have function  \"%s\"", contract.name, functionName)
	}

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

	if contract.HasDataPart() {
		dataPart, err := contract.GetDataPart()
		if err != nil {
			return res, err
		}
		// Code and data part are seperated by OP_RETURN.
		res, err = bscript.NewFromHexString(codePart + dataPart)

		if err != nil {
			return res, err
		}

	} else {
		res, err = bscript.NewFromHexString(codePart)
	}

	if err != nil {
		return res, err
	}

	return res, nil
}

func (contract *Contract) GetNewLockingScript(dataPart string) (*bscript.Script, error) {
	var res *bscript.Script

	codePart, err := contract.GetCodePart()
	if err != nil {
		return res, err
	}

	if dataPart != "" {
		// Code and data part are seperated by OP_RETURN.
		res, err = bscript.NewFromHexString(codePart + dataPart)
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
		lockingScriptHex, err = contract.substituteParamInTemplate(lockingScriptHex, param.Value, param.Name)
		if err != nil {
			return res, err
		}
	}

	if contract.HasDataPart() {
		return lockingScriptHex + "6a", nil
	}

	return lockingScriptHex, nil
}

func (contract *Contract) GetStates() (string, error) {
	// Get the data part of the locking script. This will contain all the serialized values of statefull variables of the contract.
	// The data part gets appended to the end of the locking script, seperated by OP_RETURN (0x6a).
	return buildContractState(&contract.stateProps, contract.firstCall)
}

func (contract *Contract) isStateful() bool {
	return len(contract.stateProps) > 0
}

func (contract *Contract) GetDataPart() (string, error) {
	// Get the data part of the locking script. This will contain all the serialized values of statefull variables of the contract.
	// The data part gets appended to the end of the locking script, seperated by OP_RETURN (0x6a).

	hex, err := contract.GetDataPartInHex()

	if err == nil {
		return hex, nil
	}

	asm, err := contract.GetDataPartInASM()

	if err == nil {
		b, err := bscript.NewFromASM(asm)
		return b.String(), err
	}

	return "", fmt.Errorf("no dataPart")
}

func (contract *Contract) GetDataPartInHex() (string, error) {
	// Get the data part of the locking script. This will contain all the serialized values of statefull variables of the contract.
	// The data part gets appended to the end of the locking script, seperated by OP_RETURN (0x6a).

	if contract.isStateful() {
		return contract.GetStates()
	}

	if !isStringEmpty(contract.dataPartInHex) {
		return contract.dataPartInHex, nil
	}

	return "", fmt.Errorf("no dataPartInHex")
}

func (contract *Contract) GetDataPartInASM() (string, error) {

	if !isStringEmpty(contract.dataPartInASM) {
		return contract.dataPartInASM, nil
	}

	return "", fmt.Errorf("no dataPartInASM")
}

func (contract *Contract) HasDataPart() bool {
	// Get the data part of the locking script. This will contain all the serialized values of statefull variables of the contract.
	// The data part gets appended to the end of the locking script, seperated by OP_RETURN (0x6a).
	if contract.isStateful() {
		return true
	}
	return !isStringEmpty(contract.dataPartInASM) || !isStringEmpty(contract.dataPartInHex)
}

func (contract *Contract) GetTxContext() (TxContext, error) {

	var txContext TxContext

	if !contract.IsExecutionContextSet() {
		return txContext, fmt.Errorf("no ExecutionContext setted ")
	}

	txContext = TxContext{
		Hex:           contract.executionContext.Tx.String(),
		InputIndex:    contract.executionContext.InputIdx,
		InputSatoshis: int(contract.executionContext.Tx.InputIdx(contract.executionContext.InputIdx).PreviousTxSatoshis),
	}

	if contract.HasDataPart() {

		hex, err := contract.GetDataPartInHex()

		if err == nil {
			txContext.OpReturnHex = hex

			return txContext, nil
		}

		asm, err := contract.GetDataPartInASM()

		if err == nil {
			txContext.OpReturn = asm
			return txContext, nil
		}

		return txContext, err
	}

	return txContext, nil
}

func (contract *Contract) SetDataPartInASM(asm string) {
	contract.dataPartInASM = asm
}

func (contract *Contract) SetDataPartInHex(hex string) {
	contract.dataPartInHex = hex
}

func (contract *Contract) UpdateStateVariable(variableName string, value ScryptType) error {
	// TODO: Make state variable lookup with a map instead of going through all constructor params.
	for i := range contract.stateProps {
		param := &contract.stateProps[i]

		if param.Name != variableName {
			continue
		}

		if !CompareScryptVariableTypes(param.Value, value) {
			return errors.New(fmt.Sprintf("Variable \"%s\" value must be of type %T. Actual type is %T.", variableName, param.Value, value))
		}

		param.Value = value
		contract.firstCall = false
		return nil
	}

	return errors.New(fmt.Sprintf("No variable named \"%s\".", variableName))
}

func (contract *Contract) UpdateStateVariables(states map[string]ScryptType) error {
	for key, value := range states {

		err := contract.UpdateStateVariable(key, value)

		if err != nil {
			return err
		}

	}

	return nil
}

// Returns template of a specific struct type defined in the contract.
func (contract *Contract) GetStructTypeTemplate(t string) (Struct, error) {

	t = contract.typeResolver(t)
	name := GetNameByType(t)
	_, ok := contract.typeItems[name] //should return copy

	if !ok {
		var st Struct
		return st, fmt.Errorf("struct %s does not exist", name)
	}

	st, err := contract.createDefaultValForType(t)

	return st.(Struct), err
}

func (contract *Contract) GetLibraryTypeTemplate(libraryName string) (Library, error) {
	name := GetNameByType(libraryName)
	_, ok := contract.typeItems[name] //should return copy

	if !ok {
		var l Library
		return l, fmt.Errorf("library %s does not exist", name)
	}

	l, err := contract.createDefaultValForType(libraryName)

	return l.(Library), err
}

func (contract *Contract) GetTypeTemplate(t string) (ScryptType, error) {

	st, err := contract.GetStructTypeTemplate(t)

	if err == nil {
		return st, nil
	}

	l, err := contract.GetLibraryTypeTemplate(t)

	if err == nil {
		return l, nil
	}

	return contract.createDefaultValForType(t)
}

func (contract *Contract) createDefaultValForType(typeString string) (ScryptType, error) {
	var res ScryptType

	t := contract.typeResolver(typeString)

	typeName := GetNameByType(t)

	typeItem, ok := contract.typeItems[typeName]

	if IsArrayType(t) {
		arrVal, err := constructArray(contract, t)
		if err != nil {
			return res, err
		}
		res = arrVal
	} else if ok && reflect.TypeOf(typeItem).Name() == "StructEntity" {

		stVal, err := constructStruct(contract, t)
		if err != nil {
			return res, err
		}

		res = stVal
	} else if ok && reflect.TypeOf(typeItem).Name() == "LibraryEntity" {
		libVal, err := constructLibrary(contract, t)
		if err != nil {
			return res, err
		}
		res = libVal
	} else {

		return createDefaultValForPrimitiveType(typeName)
	}

	return res, nil
}

func (contract *Contract) constructAbiPlaceholders() error {
	var constructorParams []functionParam
	publicFunctions := make(map[string]publicFunction)

	for _, abiItem := range contract.abis {

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
			pName := param.Name
			pType := param.Type

			val, err := contract.createDefaultValForType(pType)

			if err != nil {
				return err
			}

			placeholder := functionParam{
				Name:       pName,
				TypeString: pType,
				Value:      val,
			}

			if abiItemType == CONSTRUCTOR {
				constructorParams = append(constructorParams, placeholder)
			} else {
				publicFunctionPlaceholder.Params = append(publicFunctionPlaceholder.Params, placeholder)
			}
		}

		if abiItemType == FUNCTION {
			publicFunctions[publicFunctionName] = publicFunctionPlaceholder
		}
	}

	contract.constructorParams = constructorParams
	contract.publicFunctions = publicFunctions

	return nil
}

func (contract *Contract) constructStatePropsPlaceholders(stateEntities []StateEntity) error {

	stateProps := make([]StateProp, 0)

	for _, stateProp := range stateEntities {

		//var value ScryptType
		pName := stateProp.Name
		pType := stateProp.Type

		val, err := contract.createDefaultValForType(pType)

		if err != nil {
			return err
		}

		placeholder := StateProp{
			Name:       pName,
			TypeString: pType,
			Value:      val,
		}

		stateProps = append(stateProps, placeholder)
	}

	contract.stateProps = stateProps

	return nil
}

func getTypeItemsFromDesc(desc map[string]interface{}) map[string]interface{} {
	res := make(map[string]interface{})
	for _, structItem := range desc["structs"].([]StructEntity) {
		structType := structItem.Name
		res[structType] = structItem
	}

	for _, libraryItem := range desc["library"].([]LibraryEntity) {
		typeStr := libraryItem.Name
		res[typeStr] = libraryItem
	}

	aliases := ConstructAliasMap(desc["alias"].([]AliasEntity))

	for key, val := range aliases {
		if _, contains := res[val]; contains {
			res[key] = res[val]
		}
	}
	return res
}

func getTypeResolverFromDesc(desc map[string]interface{}) func(string) string {

	aliases := ConstructAliasMap(desc["alias"].([]AliasEntity))

	return func(t string) string {
		return ResolveType(t, aliases)
	}
}

func constructStruct(contract *Contract, typeString string) (Struct, error) {

	var res Struct

	var keysInOrder []string
	values := make(map[string]ScryptType)

	t := contract.typeResolver(typeString)

	name := GetNameByType(t)

	s, ok := contract.typeItems[name]

	if !ok {
		return res, fmt.Errorf("no sturct %s found", name)
	}

	structEntity := s.(StructEntity)

	genericTypes, err := DeduceGenericType(t, structEntity.GenericTypes)

	if err != nil {
		return res, err
	}

	params := make([]ParamEntity, 0)
	if len(structEntity.GenericTypes) > 0 {
		for _, P := range structEntity.Params {
			actualType := DeduceActualType(P.Type, genericTypes)
			params = append(params, ParamEntity{Name: P.Name, Type: actualType})
		}

	} else {

		params = append(params, structEntity.Params...)
	}

	for _, param := range params {
		pName := param.Name
		keysInOrder = append(keysInOrder, pName)

		val, err := contract.createDefaultValForType(param.Type)

		if err != nil {
			return res, err
		}

		values[pName] = val
	}

	gts := funk.Map(structEntity.GenericTypes, func(generic string) GenericType {
		return GenericType{
			Generic: generic,
			Actual:  genericTypes[generic],
		}
	}).([]GenericType)

	return Struct{
		typeName:     structEntity.Name,
		keysInOrder:  keysInOrder,
		values:       values,
		genericTypes: gts,
	}, nil
}

func constructLibrary(contract *Contract, typeString string) (Library, error) {

	var res Library

	t := contract.typeResolver(typeString)

	name := GetNameByType(t)

	l, ok := contract.typeItems[name]

	if !ok {
		return res, fmt.Errorf("no library %s found", name)
	}

	libraryEntity := l.(LibraryEntity)

	genericTypes, err := DeduceGenericType(t, libraryEntity.GenericTypes)

	if err != nil {
		return res, err
	}

	Params := libraryEntity.Params

	// without constructor
	if len(Params) == 0 && len(libraryEntity.Properties) > 0 {
		Params = libraryEntity.Properties
	}

	paramsKeys, params, err := constructParams(contract, Params, genericTypes)

	if err != nil {
		return res, err
	}

	propertiesKeys, properties, err := constructParams(contract, libraryEntity.Params, genericTypes)

	if err != nil {
		return res, err
	}

	gts := funk.Map(libraryEntity.GenericTypes, func(generic string) GenericType {
		return GenericType{
			Generic: generic,
			Actual:  genericTypes[generic],
		}
	}).([]GenericType)

	return Library{
		typeName:            libraryEntity.Name,
		paramKeysInOrder:    paramsKeys,
		params:              params,
		propertyKeysInOrder: propertiesKeys,
		properties:          properties,
		genericTypes:        gts,
	}, nil
}

func constructArray(contract *Contract, typeString string) (Array, error) {

	var res Array
	elemType, arraySizes := FactorizeArrayTypeString(typeString)

	var items []ScryptType
	for dimension := len(arraySizes) - 1; dimension >= 0; dimension-- {
		arraySize := arraySizes[dimension]
		nItems, _ := strconv.Atoi(arraySize)

		if dimension == len(arraySizes)-1 {
			// Last dimension. Create concrete types here.
			for i := 0; i < nItems; i++ {
				item, err := contract.createDefaultValForType(elemType)

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

func constructParams(contract *Contract, ps []ParamEntity, genericTypesMap map[string]string) ([]string, map[string]ScryptType, error) {

	values := make(map[string]ScryptType)
	keys := make([]string, 0)

	params := make([]ParamEntity, 0)

	if len(genericTypesMap) > 0 {
		for _, P := range ps {
			actualType := DeduceActualType(P.Type, genericTypesMap)
			params = append(params, ParamEntity{Name: P.Name, Type: actualType})
		}

	} else {

		params = append(params, ps...)
	}

	for _, param := range params {

		keys = append(keys, param.Name)

		val, err := contract.createDefaultValForType(param.Type)

		if err != nil {
			return keys, values, err
		}

		values[param.Name] = val
	}

	return keys, values, nil

}

func createDefaultValForPrimitiveType(typeString string) (ScryptType, error) {
	var res ScryptType
	switch typeString {
	case "bool":
		res = Bool{true}
	case "int":
		res = Int{big.NewInt(0)}
	case "bytes":
		res = Bytes{[]byte{0x00}}
	case "PrivKey":
		res = PrivKey{nil}
	case "PubKey":
		res = PubKey{nil}
	case "Sig":
		res = Sig{nil, 0}
	case "Ripemd160":
		res = Ripemd160{[]byte{0x00}}
	case "Sha1":
		res = Sha1{[]byte{0x00}}
	case "Sha256":
		res = Sha256{[]byte{0x00}}
	case "SigHashType":
		res = SigHashType{[]byte{0x00}}
	case "SigHashPreimage":
		res = SigHashPreimage{[]byte{0x00}}
	case "OpCodeType":
		res = OpCodeType{[]byte{0x00}}
	default:
		return res, fmt.Errorf("unknown type string \"%s\"", typeString)
	}
	return res, nil
}

// Creates a new instance of Contract type from the contracts description tree.
func NewContractFromDesc(desc map[string]interface{}) (Contract, error) {
	var res Contract

	lockingScriptHexTemplate := desc["hex"].(string)

	typeItems := getTypeItemsFromDesc(desc)

	typeResolver := getTypeResolverFromDesc(desc)

	abis := desc["abi"].([]ABIEntity)

	c := Contract{
		file:                     desc["file"].(string),
		name:                     desc["contract"].(string),
		lockingScriptHexTemplate: lockingScriptHexTemplate,
		abis:                     abis,
		constructorParams:        make([]functionParam, 0),
		stateProps:               make([]StateProp, 0),
		publicFunctions:          make(map[string]publicFunction),
		typeResolver:             typeResolver,
		typeItems:                typeItems,
		contextSet:               false,
		firstCall:                true,
	}

	err := c.constructAbiPlaceholders()

	if err != nil {
		return res, err
	}

	err = c.constructStatePropsPlaceholders(desc["stateProps"].([]StateEntity))

	if err != nil {
		return res, err
	}

	return c, nil
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

func (contract *Contract) substituteParamInTemplate(lockingScriptHex string, elem ScryptType, paramName string) (string, error) {

	switch reflect.TypeOf(elem).Name() {
	case "Struct":
		return contract.substituteStructParamInTemplate(lockingScriptHex, elem.(Struct), paramName)
	case "Library":
		return contract.substituteLibraryParamInTemplate(lockingScriptHex, elem.(Library), paramName)
	case "Array":
		arr := elem.(Array)
		return contract.substituteArrayParamInTemplate(lockingScriptHex, arr, paramName)

	default:

		// If this parameter is part of the contracts state, then we only have to substitute the placeholder with an arbitrary
		// value. This value gets replaced by the actual vale in the state part of the script during a contract call evaluation.
		elemHex, err := elem.Hex()
		if err != nil {
			return "", err
		}

		toReplace := fmt.Sprintf("<%s>", paramName)
		return strings.Replace(lockingScriptHex, toReplace, elemHex, 1), nil
	}

}

func subscript(index int, arraySizes []string) string {

	if len(arraySizes) > 1 {
		subArraySizes := arraySizes[1:]
		offset := funk.Reduce(subArraySizes, func(acc int, val string) int {
			size, _ := strconv.Atoi(val)
			return acc * size
		}, 1).(int)
		return fmt.Sprintf("[%d]%s", index/offset, subscript(index%offset, subArraySizes))
	}

	return fmt.Sprintf("[%d]", index)
}

func (contract *Contract) substituteArrayParamInTemplate(lockingScriptHex string, arr Array, paramName string) (string, error) {
	elems := FlattenArray(arr)
	_, sizes := FactorizeArrayTypeString(arr.GetTypeString())
	for i := 0; i < len(elems); i++ {
		elem := elems[i]

		subScript := subscript(i, sizes)
		toReplace := fmt.Sprintf("%s%s", paramName, subScript)

		switch reflect.TypeOf(elem).Name() {
		case "Struct":
			res, err := contract.substituteStructParamInTemplate(lockingScriptHex, elem.(Struct), toReplace)

			if err != nil {
				return lockingScriptHex, nil
			}
			lockingScriptHex = res
		case "Library":
			res, err := contract.substituteLibraryParamInTemplate(lockingScriptHex, elem.(Library), toReplace)
			if err != nil {
				return lockingScriptHex, nil
			}
			lockingScriptHex = res
		case "Array":
			arr := elem.(Array)
			res, err := contract.substituteArrayParamInTemplate(lockingScriptHex, arr, toReplace)
			if err != nil {
				return lockingScriptHex, nil
			}
			lockingScriptHex = res
		default:

			elemHex, err := elem.Hex()
			if err != nil {
				return "", err
			}
			lockingScriptHex = strings.Replace(lockingScriptHex, "<"+toReplace+">", elemHex, 1)
		}
	}

	return lockingScriptHex, nil
}

func (contract *Contract) substituteStructParamInTemplate(lockingScriptHex string, structItem Struct, paramName string) (string, error) {
	for _, key := range structItem.keysInOrder {
		toReplace := fmt.Sprintf("%s.%s", paramName, key)
		val := structItem.values[key]

		switch reflect.TypeOf(val).Name() {
		case "Struct":
			res, err := contract.substituteStructParamInTemplate(lockingScriptHex, val.(Struct), toReplace)

			if err != nil {
				return lockingScriptHex, nil
			}
			lockingScriptHex = res
		case "Array":
			arr := val.(Array)
			res, err := contract.substituteArrayParamInTemplate(lockingScriptHex, arr, toReplace)
			if err != nil {
				return lockingScriptHex, nil
			}
			lockingScriptHex = res
		default:

			elemHex, err := val.Hex()
			if err != nil {
				return "", err
			}
			lockingScriptHex = strings.Replace(lockingScriptHex, "<"+toReplace+">", elemHex, 1)
		}
	}

	return lockingScriptHex, nil
}

func (contract *Contract) substituteLibraryParamInTemplate(lockingScriptHex string, libraryItem Library, paramName string) (string, error) {
	for _, key := range libraryItem.paramKeysInOrder {

		val := libraryItem.params[key]

		toReplace := fmt.Sprintf("%s.%s", paramName, key)

		switch reflect.TypeOf(val).Name() {
		case "Struct":
			res, err := contract.substituteStructParamInTemplate(lockingScriptHex, val.(Struct), toReplace)

			if err != nil {
				return lockingScriptHex, nil
			}
			lockingScriptHex = res
		case "Library":
			res, err := contract.substituteLibraryParamInTemplate(lockingScriptHex, val.(Library), toReplace)
			if err != nil {
				return lockingScriptHex, nil
			}
			lockingScriptHex = res
		case "Array":
			arr := val.(Array)
			res, err := contract.substituteArrayParamInTemplate(lockingScriptHex, arr, toReplace)
			if err != nil {
				return lockingScriptHex, nil
			}
			lockingScriptHex = res
		default:

			elemHex, err := val.Hex()
			if err != nil {
				return "", err
			}
			lockingScriptHex = strings.Replace(lockingScriptHex, "<"+toReplace+">", elemHex, 1)
		}

	}

	return lockingScriptHex, nil
}

func (contract *Contract) getNewStateScript(states map[string]ScryptType) (*bscript.Script, error) {

	if len(contract.stateProps) == 0 {
		return nil, fmt.Errorf("contract %s does not have state properties", contract.name)
	}

	stateProps := funk.Map(contract.stateProps, func(prop StateProp) StateProp {

		clone := prop

		if val, ok := states[prop.Name]; ok {
			clone.Value = val
		}

		return clone
	}).([]StateProp)

	hex, err := buildContractState(&stateProps, false)

	if err != nil {
		return nil, err
	}

	var res *bscript.Script

	codePart, err := contract.GetCodePart()
	if err != nil {
		return res, err
	}

	return bscript.NewFromHexString(codePart + hex)

}
