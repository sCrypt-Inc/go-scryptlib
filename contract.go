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
	name                     string
	lockingScriptHexTemplate string
	executedPubFunc          string
	dataPartInASM            string
	dataPartInHex            string
	aliases                  map[string]string
	constructorParams        []functionParam
	stateProps               []StateProp
	publicFunctions          map[string]publicFunction
	structTypes              map[string]Struct // Templates of contracts struct types.
	// Maps struct names to related templates.
	libraryTypes     map[string]Library // Templates of contracts libraries.
	executionContext ExecutionContext
	file             string
	contextSet       bool
	firstCall        bool
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

		// fmt.Println("unlockingScript", hex.EncodeToString(*unlockingScript))
		// fmt.Println("lockingScript", hex.EncodeToString(*prevLockingScript))
		// fmt.Println("Tx", contract.executionContext.Tx.String())
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

// Get templates of all struct types defined in the contract. Returns map with struct type names as keys and templates as values.
func (contract *Contract) GetStructTypeTemplates() map[string]Struct {
	res := make(map[string]Struct)
	for key, value := range contract.structTypes {
		res[key] = value
	}
	return res
}

// Returns template of a specific struct type defined in the contract.
func (contract *Contract) GetStructTypeTemplate(structName string) (Struct, error) {
	s, ok := contract.structTypes[structName] //should return copy

	if !ok {
		return s, fmt.Errorf("struct %s does not exist", structName)
	}
	return s, nil
}

func (contract *Contract) GetLibraryTypeTemplate(libraryName string) (Library, error) {
	l, ok := contract.libraryTypes[libraryName] //should return copy
	if !ok {
		return l, fmt.Errorf("library %s does not exist", libraryName)
	}
	return l, nil
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

			if IsArrayType(pType) {
				arrVal, err := constructArrayType(pType, structDescItemsByTypeString, libraryDescItemsByTypeString, aliases)
				if err != nil {
					return nil, publicFunctions, err
				}
				value = arrVal
			} else if isStructType {
				value = structItem
			} else if isLibraryType {
				value = libaryItem
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

	return constructorParams, publicFunctions, nil
}

func constructStatePropsPlaceholders(desc map[string]interface{},
	structItems map[string]Struct,
	libaryItems map[string]Library,
	aliases map[string]string) ([]StateProp, error) {

	stateProps := make([]StateProp, 0)

	structDescItemsByTypeString := getStructItemsByTypeString(desc)
	libraryDescItemsByTypeString := getLibraryItemsByTypeString(desc)

	for _, stateProp := range desc["stateProps"].([]StateEntity) {

		var value ScryptType
		pName := stateProp.Name
		pType := stateProp.Type

		structItem, isStructType := structItems[pType]
		libaryItem, isLibraryType := libaryItems[pType]

		if IsArrayType(pType) {
			arrVal, err := constructArrayType(pType, structDescItemsByTypeString, libraryDescItemsByTypeString, aliases)
			if err != nil {
				return nil, err
			}
			value = arrVal
		} else if isStructType {
			value = structItem
		} else if isLibraryType {
			value = libaryItem
		} else {
			// Concrete values.
			val, err := createPrimitiveTypeWDefaultVal(pType)
			if err != nil {
				return nil, err
			}
			value = val
		}

		placeholder := StateProp{
			Name:       pName,
			TypeString: pType,
			Value:      value,
		}

		stateProps = append(stateProps, placeholder)
	}

	return stateProps, nil
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

		typeDescItemField, isParamStructType := structDescItemsByTypeString[pType]

		var val ScryptType
		var err error

		if IsArrayType(pTypeResolved) {
			emptyDescItemsByTypeString := make(map[string]LibraryEntity)
			val, err = constructArrayType(pTypeResolved, structDescItemsByTypeString, emptyDescItemsByTypeString, aliases)
		} else if isParamStructType {
			val, err = constructStructTypeItem(typeDescItemField, structDescItemsByTypeString, aliases)
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

func constructParamsTypeItem(params []ParamEntity,
	structDescItemsByTypeString map[string]StructEntity,
	libraryDescItemsByTypeString map[string]LibraryEntity,
	aliases map[string]string) ([]string, map[string]ScryptType, error) {

	values := make(map[string]ScryptType)
	keys := make([]string, 0)

	for _, param := range params {
		pName := param.Name
		pType := param.Type

		keys = append(keys, pName)
		pTypeResolved := ResolveType(pType, aliases)

		structDescItem, isParamStructType := structDescItemsByTypeString[pTypeResolved]
		libraryDescItem, isParamLibraryType := libraryDescItemsByTypeString[pTypeResolved]

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
			return keys, values, err
		}

		values[pName] = val
	}

	return keys, values, nil

}

func constructLibraryTypeItem(typeDescItem LibraryEntity,
	structDescItemsByTypeString map[string]StructEntity,
	libraryDescItemsByTypeString map[string]LibraryEntity,
	aliases map[string]string) (Library, error) {

	var res Library

	Params := typeDescItem.Params

	// without constructor
	if len(Params) == 0 && len(typeDescItem.Properties) > 0 {
		Params = typeDescItem.Properties
	}
	paramsKeys, params, err := constructParamsTypeItem(Params,
		structDescItemsByTypeString, libraryDescItemsByTypeString, aliases)

	if err != nil {
		return res, err
	}

	propertiesKeys, properties, err := constructParamsTypeItem(typeDescItem.Properties,
		structDescItemsByTypeString, libraryDescItemsByTypeString, aliases)

	if err != nil {
		return res, err
	}

	return Library{
		typeName:            typeDescItem.Name,
		paramKeysInOrder:    paramsKeys,
		params:              params,
		propertyKeysInOrder: propertiesKeys,
		properties:          properties,
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

// func createPrimitiveTypeWDefaultVal(typeString string) (ScryptType, error) {
// 	var res ScryptType
// 	switch typeString {
// 	case "bool":
// 		res = Bool{true}
// 	case "int":
// 		res = Int{big.NewInt(0)}
// 	case "bytes":
// 		res = Bytes{make([]byte, 0)}
// 	case "PrivKey":
// 		res = PrivKey{nil}
// 	case "PubKey":
// 		res = PubKey{nil}
// 	case "Sig":
// 		res = Sig{nil, 0}
// 	case "Ripemd160":
// 		res = Ripemd160{make([]byte, 0)}
// 	case "Sha1":
// 		res = Sha1{make([]byte, 0)}
// 	case "Sha256":
// 		res = Sha256{make([]byte, 0)}
// 	case "SigHashType":
// 		res = SigHashType{make([]byte, 0)}
// 	case "SigHashPreimage":
// 		res = SigHashPreimage{make([]byte, 0)}
// 	case "OpCodeType":
// 		res = OpCodeType{make([]byte, 0)}
// 	default:
// 		return res, fmt.Errorf("unknown type string \"%s\"", typeString)
// 	}
// 	return res, nil
// }

func createPrimitiveTypeWDefaultVal(typeString string) (ScryptType, error) {
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

	stateProps, err := constructStatePropsPlaceholders(desc, structItems, libaryItems, aliases)

	if err != nil {
		return res, err
	}

	return Contract{
		file:                     desc["file"].(string),
		name:                     desc["contract"].(string),
		lockingScriptHexTemplate: lockingScriptHexTemplate,
		aliases:                  aliases,
		constructorParams:        constructorParams,
		stateProps:               stateProps,
		publicFunctions:          publicFunctions,
		structTypes:              structItems,
		libraryTypes:             libaryItems,
		contextSet:               false,
		firstCall:                true,
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

func (contract *Contract) substituteArrayParamInTemplate(lockingScriptHex string, arr Array, paramName string) (string, error) {
	elems := FlattenArray(arr)
	_, sizes := FactorizeArrayTypeString(arr.GetTypeString())
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
