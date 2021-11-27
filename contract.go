package scryptlib

import (
    "fmt"
    "errors"
    "strconv"
    "reflect"
    "strings"
    "math/big"
    "encoding/binary"

    "github.com/libsv/go-bt/v2"
    "github.com/libsv/go-bt/v2/bscript"
    "github.com/libsv/go-bt/v2/bscript/interpreter"
    "github.com/libsv/go-bt/v2/bscript/interpreter/scriptflag"
)


type functionParam struct {
    Name        string
    TypeString  string
    Value       ScryptType
    IsState     bool
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
    Params       []functionParam    // TODO: Maybe make this a map, because order is set by the hex template.
}

type ExecutionContext struct {
	Tx              *bt.Tx
	InputIdx        int
	Flags           scriptflag.Flag
}

type Contract struct {
    lockingScriptHexTemplate  string
    aliases                   map[string]string
    constructorParams         []functionParam
    publicFunctions           map[string]publicFunction
    structTypes               map[string]Struct             // Templates of contracts struct types. Maps struct names to related templates.
    executionContext          ExecutionContext
    contextSet                bool
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
            if ! same {
                errMsg := fmt.Sprintf("Passed Struct value for param with name \"%s\" is not of the right structure.",
                                    paramPlaceholder.Name)
                return errors.New(errMsg)
            }
        } else if typePlaceholder == "Array" {
            same := IsArraySameStructure(paramPlaceholder.Value.(Array), value.(Array))
            if ! same {
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
            if ! same {
                errMsg := fmt.Sprintf("Passed Struct value for param with name \"%s\" is not of the right structure.",
                                    paramPlaceholder.Name)
                return errors.New(errMsg)
            }
        } else if typePlaceholder == "Array" {
            same := IsArraySameStructure(paramPlaceholder.Value.(Array), value.(Array))
            if ! same {
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

    if ! contract.contextSet {
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
        lockingScriptHex, err = substituteParamInTemplate(lockingScriptHex, param.Value, param.Name, param.IsState)
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
        if ! param.IsState {
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

        if ! param.IsState {
            return errors.New(fmt.Sprintf("\"%s\" is not a state variable.", variableName))
        }

        if ! CompareScryptVariableTypes(param.Value, value) {
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

func constructAbiPlaceholders(desc map[string]interface{}, structTypes map[string]Struct,
                                    aliases map[string]string) ([]functionParam, map[string]publicFunction, error) {
    var constructorParams []functionParam
    publicFunctions := make(map[string]publicFunction)

    // TODO: Pass this as a pram instead of recreating it here.
    structItemsByTypeString := getStructItemsByTypeString(desc)

    for _, abiItem := range desc["abi"].([]map[string]interface{}) {

        abiItemType := abiItem["type"].(string)
        params := abiItem["params"].([]map[string]interface{})

        var publicFunctionPlaceholder publicFunction
        var publicFunctionName string
        if abiItemType == "function" {
            publicFunctionName = abiItem["name"].(string)
            publicFunctionPlaceholder = publicFunction{
                                            FunctionName: publicFunctionName,
                                            Index: abiItem["index"].(int),
                                        }
        }

        for _, param := range params {
            var value ScryptType
            pName := param["name"].(string)
            pType := param["type"].(string)

            if IsStructType(pType) {
                // Create copy of struct template.
                structName := GetStructNameByType(pType)
                value = structTypes[structName]
                // We only want the name of the struct as the param type
                // and not the whole desc type string.
                pType = GetStructNameByType(pType)
            } else if IsArrayType(pType) {
                arrVal, err := constructArrayType(pType, structItemsByTypeString, aliases)
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
                placeholder.IsState = param["state"].(bool)
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

func getStructItemsByTypeString(desc map[string]interface{}) map[string]interface{} {
    structItemsByTypeString := make(map[string]interface{})
    for _, structItem := range desc["structs"].([]map[string]interface{}) {
        structType := structItem["name"].(string)
        structItemsByTypeString[structType] = structItem
    }
    return structItemsByTypeString
}


func constructStructTypes(structItemsByTypeString map[string]interface{}, aliases map[string]string) (map[string]Struct, error) {
    res := make(map[string]Struct)

    for structName, structItem := range structItemsByTypeString {
        structItem := structItem.(map[string]interface{})
        structType, err := constructStructType(structItem, structItemsByTypeString, aliases)
        if err != nil {
            return res, err
        }
        res[structName] = structType
    }

    return res, nil
}

func constructStructType(structItem map[string]interface{}, structItemsByTypeString map[string]interface{},
                                                    aliases map[string]string) (Struct, error) {

    var res Struct

    var keysInOrder []string
    values := make(map[string]ScryptType)

    params := structItem["params"].([]map[string]string)
    for _, param := range params {
        pName := param["name"]
        pType := param["type"]
        pTypeResolved := ResolveType(pType, aliases)

        keysInOrder = append(keysInOrder, pName)

        var val ScryptType
        var err error

        if IsStructType(pTypeResolved) {
            structItem := structItemsByTypeString[pTypeResolved]
            val, err = constructStructType(structItem.(map[string]interface{}), structItemsByTypeString, aliases)
        } else if IsArrayType(pTypeResolved) {
            val, err = constructArrayType(pTypeResolved, structItemsByTypeString, aliases)
        } else {
            val, err = createPrimitiveTypeWDefaultVal(pTypeResolved)
        }

        if err != nil {
            return res, err
        }

        values[pName] = val
    }

    return Struct{
        typeName:    structItem["name"].(string),
        keysInOrder: keysInOrder,
        values:      values,
    }, nil
}

func constructArrayType(typeString string, structItemsByTypeString map[string]interface{},
                                       aliases map[string]string) (Array, error) {
    var res Array
    typeName, arraySizes := FactorizeArrayTypeString(typeString)
    if IsStructType(typeName) {
        typeName = GetStructNameByType(typeName)
    }

    var items []ScryptType
    for dimension := len(arraySizes) - 1; dimension >= 0; dimension-- {
        arraySize := arraySizes[dimension]
        nItems, _ := strconv.Atoi(arraySize)

        if dimension == len(arraySizes) - 1 {
            // Last dimension. Create concrete types here.
            for i := 0; i < nItems; i++ {
                var item ScryptType
                var err error

                structItem, isStructType := structItemsByTypeString[typeName]
                if isStructType {
                    item, err = constructStructType(structItem.(map[string]interface{}), structItemsByTypeString, aliases)
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
    aliases := ConstructAliasMap(desc["alias"].([]map[string]string))

    structItemsByTypeString := getStructItemsByTypeString(desc)

    // Construct instances of struct types.
    structTypes, err := constructStructTypes(structItemsByTypeString, aliases)
    if err != nil {
        return res, err
    }

    // structTypes should also contain keys for aliases.
    // TODO: Fix aliases for concrete vals.
    for key, val := range aliases {
        structTypes[key] = structTypes[val]
    }

    // Initialize constructor parameter placeholders and public functions along its parameter placeholders.
    constructorParams, publicFunctions, err := constructAbiPlaceholders(desc, structTypes, aliases)
    if err != nil {
        return res, err
    }

    return Contract{
        lockingScriptHexTemplate: lockingScriptHexTemplate,
        aliases: aliases,
        constructorParams: constructorParams,
        publicFunctions: publicFunctions,
        structTypes: structTypes,
        contextSet: false,
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

func substituteParamInTemplate(lockingScriptHex string, elem ScryptType, paramName string, isState bool) (string, error) {
    typeStr := elem.GetTypeString()
    if IsBasicScryptType(typeStr) {
        // If this parameter is part of the contracts state, then we only have to substitute the placeholder with an arbitrary
        // value. This value gets replaced by the actual vale in the state part of the script during a contract call evaluation.
        elemHex := "00"
        if ! isState {
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
        return substituteArrayParamInTemplate(lockingScriptHex, arr, paramName, isState)
    } else {
        structItem := elem.(Struct)
        return substituteStructParamInTemplate(lockingScriptHex, structItem, paramName, isState)
    }
}

func substituteArrayParamInTemplate(lockingScriptHex string, arr Array, paramName string, isState bool) (string, error) {
    elems := FlattenArray(arr)
    elemTypeName, sizes := FactorizeArrayTypeString(arr.GetTypeString())
    // TODO: Make checking for struct type strings simpler.
    if IsStructType(elemTypeName) {
        elemTypeName = GetStructNameByType(elemTypeName)
    }
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
                lockingScriptHex = strings.Replace(lockingScriptHex, "<" + toReplace + ">", "00", 1)
            } else {
                lockingScriptHex = strings.Replace(lockingScriptHex, "<" + toReplace + ">", elemHex, 1)
            }
        } else {
            // Structs.
            var err error
            lockingScriptHex, err = substituteStructParamInTemplate(lockingScriptHex, elem.(Struct), toReplace,isState)
            if err != nil {
                return "", err
            }
        }
    }

    return lockingScriptHex, nil
}

func substituteStructParamInTemplate(lockingScriptHex string, structItem Struct, paramName string, isState bool) (string, error) {
    for _, key := range structItem.keysInOrder {
        toReplace := fmt.Sprintf("%s.%s", paramName, key)
        val := structItem.values[key]

        if IsArrayType(val.GetTypeString()) {
            res, err := substituteArrayParamInTemplate(lockingScriptHex, val.(Array), toReplace, isState)
            if err != nil {
                return "", err
            }
            lockingScriptHex = res
        } else {
            if isState {
                lockingScriptHex = strings.Replace(lockingScriptHex, "<" + toReplace + ">", "00", 1)
            } else {
                valHex, err := val.Hex()
                if err != nil {
                    return "", err
                }
                lockingScriptHex = strings.Replace(lockingScriptHex, "<" + toReplace + ">", valHex, 1)
            }
        }
    }

    return lockingScriptHex, nil
}

