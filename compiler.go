package scryptlib

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// TODO: Close files without defer.
// TODO: Don't use pointers with maps, as they themselves are reference types.

var CURRENT_CONTRACT_DESCRIPTION_VERSION = 8

var SOURCE_REGEXP = regexp.MustCompile(`^(?P<fileIndex>-?\d+):(?P<line>\d+):(?P<col>\d+):(?P<endLine>\d+):(?P<endCol>\d+)(#(?P<tagStr>.+))?`)
var WARNING_REGEXP = regexp.MustCompile(`Warning:(\s|\n)*(?P<filePath>[^\s]+):(?P<line>\d+):(?P<column>\d+):(?P<line1>\d+):(?P<column1>\d+):*\n(?P<message>[^\n]+)\n`)

var DebugModeTag = map[string]string{
	"FUNC_START": "F0",
	"FUNC_END":   "F1",
	"LOOP_START": "L0",
}

type BuildType string

const (
	Debug   BuildType = "debug"
	Release BuildType = "release"
)

type ParamEntity struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type StateEntity = ParamEntity

type StructEntity struct {
	Name   string        `json:"name"`
	Params []ParamEntity `json:"params"`
}

type AliasEntity struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type LibraryEntity struct {
	Name       string        `json:"name"`
	Params     []ParamEntity `json:"params"`
	Properties []ParamEntity `json:"properties"`
}

type ABIEntityType string

const (
	FUNCTION    ABIEntityType = "function"
	CONSTRUCTOR ABIEntityType = "constructor"
)

type ABIEntity struct {
	Name   string        `json:"name"`
	Type   ABIEntityType `json:"type"`
	Params []ParamEntity `json:"params"`
	Index  int           `json:"index"`
}

type CompilerResult struct {
	Ast             map[string]interface{}   // ASTs from all the compiled source files
	Asm             []map[string]interface{} // ASM data of the compiled contract
	DepAst          map[string]interface{}   // ASTs only of dependencies
	Abi             []ABIEntity              // ABI of the contract
	Warnings        []CompilerWarning        // Warnings returned by the compiler
	CompilerVersion string                   // Version of the compiler binary used to compile the contract
	Contract        string                   // Name of the compiled contract
	StateProps      []StateEntity            // state properties of the compiled contract
	Structs         []StructEntity           // Struct declarations
	Libraries       []LibraryEntity          // Library declarations
	Aliases         []AliasEntity            // Aliases used in the contract
	buildType       BuildType                // buildType
	SourceFile      string                   // URI of the contracts source file
	AutoTypedVars   []map[string]interface{} // Variables with infered type
	SourceMD5       string                   // MD5 hash of the contracts source code
	RawAsm          string                   // Raw locking script in ASM format with parameter placeholders
	RawHex          string                   // Raw locking script in hexadecimal format with parameter placeholders
	CompilerOutAsm  map[string]interface{}   // Whole ASM tree, as outputed by the compiler
}

func (compilerResult CompilerResult) ToDesc() map[string]interface{} {
	res := make(map[string]interface{})
	res["version"] = CURRENT_CONTRACT_DESCRIPTION_VERSION
	res["compilerVersion"] = compilerResult.CompilerVersion
	res["contract"] = compilerResult.Contract
	res["md5"] = compilerResult.SourceMD5
	res["stateProps"] = compilerResult.StateProps
	res["structs"] = compilerResult.Structs
	res["library"] = compilerResult.Libraries
	res["alias"] = compilerResult.Aliases
	res["abi"] = compilerResult.Abi
	res["buildType"] = compilerResult.buildType
	res["file"] = ""
	res["asm"] = compilerResult.RawAsm
	res["hex"] = compilerResult.RawHex
	res["sources"] = nil
	res["sourceMap"] = nil
	return res
}

func (compilerResult CompilerResult) ToDescWSourceMap() (map[string]interface{}, error) {
	res := compilerResult.ToDesc()

	output := compilerResult.CompilerOutAsm["output"].([]interface{})
	if len(output) == 0 {
		return res, nil
	}

	firstElem := output[0].(map[string]interface{})
	if _, ok := firstElem["src"]; !ok {
		return nil, errors.New("Missing source map data in compiler results. Run compiler with debug flag.")
	}

	var sources []string
	for _, source := range compilerResult.CompilerOutAsm["sources"].([]interface{}) {
		sources = append(sources, source.(string))
	}
	sourcesFullpath, err := getSourcesFullpath(sources)
	if err != nil {
		return nil, err
	}

	res["file"] = compilerResult.SourceFile
	res["sources"] = sourcesFullpath

	var sourceMap []string
	for _, item := range compilerResult.CompilerOutAsm["output"].([]interface{}) {
		item := item.(map[string]interface{})
		sourceMap = append(sourceMap, item["src"].(string))
	}
	res["sourceMap"] = sourceMap

	return res, nil
}

type ResultsAst struct {
	Ast              map[string]interface{}
	DepAst           map[string]interface{}
	Aliases          []AliasEntity
	Abi              []ABIEntity
	Structs          []StructEntity
	Libraries        []LibraryEntity
	StateProps       []StateEntity
	MainContractName string
}

type ResultsAsm struct {
	Asm           []map[string]interface{}
	AsmTree       map[string]interface{}
	AutoTypedVars []map[string]interface{}
	AsmRaw        string
	HexRaw        string
}

type CompilerWarning struct {
	FilePath string
	Line0    int
	Col0     int
	Line1    int
	Col1     int
	Message  string
}

type CompilerWrapper struct {
	// Path to the scryptc compiler binary file.
	// If left empty the SDK will try to search for it.
	CompilerBin string
	// Location of stored compiler outputs and desc file.
	OutDir   string
	Asm      bool
	HexOut   bool
	Debug    bool
	Optimize bool
	Ast      bool
	// If true, write desc file to OutDir.
	Desc         bool
	CmdArgs      string
	Cwd          string
	ContractPath string
}

func (compilerWrapper *CompilerWrapper) compile(source string, sourceFilePrefix string, fromFile bool) (CompilerResult, error) {
	var res CompilerResult

	// Create outDir, if it doesn't exist yet.
	if _, err := os.Stat(compilerWrapper.OutDir); os.IsNotExist(err) {
		err := os.Mkdir(compilerWrapper.OutDir, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}

	var contractPath string
	if fromFile {
		var err error
		contractPath, err = filepath.Abs(source)
		if err != nil {
			return res, err
		}
		compilerWrapper.ContractPath = contractPath
	} else {
		compilerWrapper.ContractPath = "stdin"
	}

	// Assemble compiler command.
	compilerCmd := compilerWrapper.assembleCompilerCommand(contractPath)

	// Run the assembled command.
	compilerCmdParts := strings.Split(compilerCmd, " ")
	cmd := exec.Command(compilerCmdParts[0], compilerCmdParts[1:]...)

	if !fromFile {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return res, err
		}
		go func() {
			defer stdin.Close()
			io.WriteString(stdin, source)
		}()
	}

	compilerStdout, err := cmd.CombinedOutput()
	if err != nil {
		return res, err
	}

	// Check compiler stdout for errors and warnings.
	warnings, err := compilerWrapper.extractCompilerWarnings(string(compilerStdout))
	if err != nil {
		return res, err
	}

	// Process results to desc file.
	outPathAst := filepath.Join(compilerWrapper.OutDir, fmt.Sprintf("%s_ast.json", sourceFilePrefix))
	outPathAsm := filepath.Join(compilerWrapper.OutDir, fmt.Sprintf("%s_asm.json", sourceFilePrefix))

	resultsAst, err := compilerWrapper.collectResultsAst(outPathAst)
	if err != nil {
		return res, err
	}
	resultsAsm, err := compilerWrapper.collectResultsAsm(outPathAsm)
	if err != nil {
		return res, err
	}

	compilerVersion, err := compilerWrapper.GetCompilerVersion()
	if err != nil {
		return res, err
	}

	var sourceMD5 string
	if fromFile {
		sourceMD5, err = compilerWrapper.getSourceFileMD5(contractPath)
	} else {
		sourceMD5, err = compilerWrapper.getSourceMD5(contractPath)
	}
	if err != nil {
		return res, err
	}

	res = CompilerResult{
		Ast:             resultsAst.Ast,
		Asm:             resultsAsm.Asm,
		DepAst:          resultsAst.DepAst,
		Abi:             resultsAst.Abi,
		buildType:       Debug,
		Warnings:        warnings,
		CompilerVersion: compilerVersion,
		Contract:        resultsAst.MainContractName,
		Structs:         resultsAst.Structs,
		Libraries:       resultsAst.Libraries,
		Aliases:         resultsAst.Aliases,
		StateProps:      resultsAst.StateProps,
		SourceFile:      fmt.Sprintf("file://%s", contractPath),
		AutoTypedVars:   resultsAsm.AutoTypedVars,
		SourceMD5:       sourceMD5,
		RawAsm:          resultsAsm.AsmRaw,
		RawHex:          resultsAsm.HexRaw,
		CompilerOutAsm:  resultsAsm.AsmTree,
	}

	if compilerWrapper.Desc {
		outFileDesc := fmt.Sprintf("%s_desc.json", sourceFilePrefix)
		outFileDesc = filepath.Join(compilerWrapper.OutDir, outFileDesc)

		var desc map[string]interface{}
		if compilerWrapper.Debug {
			desc, err = res.ToDescWSourceMap()
			if err != nil {
				return res, err
			}
		} else {
			desc = res.ToDesc()
		}

		f, err := os.Create(outFileDesc)
		if err != nil {
			return res, err
		}

		defer func() {
			if err = f.Close(); err != nil {
				log.Fatal(err)
			}
		}()

		descJSON, _ := json.MarshalIndent(desc, "", "  ")
		_, err = f.WriteString(string(descJSON))
		if err != nil {
			return res, err
		}

		f.Sync()
	}

	return res, nil
}

func (compilerWrapper *CompilerWrapper) CompileContractFile(contractPath string) (CompilerResult, error) {
	sourceFilePrefix := compilerWrapper.getSourceFilePrefix(contractPath)
	return compilerWrapper.compile(contractPath, sourceFilePrefix, true)
}

func (compilerWrapper *CompilerWrapper) CompileContractString(contractCode string) (CompilerResult, error) {
	return compilerWrapper.compile(contractCode, "stdin", false)
}

func (compilerWrapper *CompilerWrapper) extractCompilerWarnings(compilerStdout string) ([]CompilerWarning, error) {
	var warnings []CompilerWarning

	matches := reSubMatchMapAll(WARNING_REGEXP, compilerStdout)
	for _, match := range matches {
		filePath := match["filePath"]

		line0, err := strconv.Atoi(match["line"])
		if err != nil {
			return warnings, err
		}
		col0, err := strconv.Atoi(match["column"])
		if err != nil {
			return warnings, err
		}
		line1, err := strconv.Atoi(match["line1"])
		if err != nil {
			return warnings, err
		}
		col1, err := strconv.Atoi(match["column1"])
		if err != nil {
			return warnings, err
		}

		message := match["message"]

		warning := CompilerWarning{
			FilePath: filePath,
			Line0:    line0,
			Col0:     col0,
			Line1:    line1,
			Col1:     col1,
			Message:  message,
		}
		warnings = append(warnings, warning)
	}

	return warnings, nil
}

func (compilerWrapper *CompilerWrapper) getSourceFileMD5(contractPath string) (string, error) {
	fileContract, err := os.Open(contractPath)
	if err != nil {
		return "", err
	}

	defer func() {
		if err = fileContract.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	source, err := io.ReadAll(fileContract)
	if err != nil {
		return "", err
	}

	return compilerWrapper.getSourceMD5(string(source))
}

func (compilerWrapper *CompilerWrapper) getSourceMD5(source string) (string, error) {
	sourceBytes := []byte(source)

	hasher := md5.New()
	hasher.Write(sourceBytes)

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (compilerWrapper *CompilerWrapper) GetCompilerVersion() (string, error) {
	stdout, err := exec.Command(compilerWrapper.CompilerBin, "version").Output()
	if err != nil {
		return "", err
	}

	tokens := strings.Fields(string(stdout))
	return tokens[1], nil
}

func (compilerWrapper *CompilerWrapper) collectResultsAst(outPathAst string) (ResultsAst, error) {
	var res ResultsAst

	fileAst, err := os.Open(outPathAst)
	if err != nil {
		return res, err
	}

	defer func() {
		if err = fileAst.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	contentAst, err := io.ReadAll(fileAst)
	if err != nil {
		return res, err
	}

	var astTree map[string]interface{}
	json.Unmarshal(contentAst, &astTree)

	srcAstRoot := astTree[compilerWrapper.ContractPath].(map[string]interface{})

	aliasesDesc := compilerWrapper.getAliases(&astTree)
	aliasMap := ConstructAliasMap(aliasesDesc)
	staticIntConsts := compilerWrapper.getStaticIntConstDeclarations(&astTree)
	mainContractName, abi := compilerWrapper.getAbiDeclaration(&srcAstRoot, aliasMap, &staticIntConsts)
	structs := compilerWrapper.getAstStructDeclarations(&astTree)
	libraries := compilerWrapper.getAstLibraryDeclarations(&astTree)
	stateProps, err := compilerWrapper.getStateProps(&srcAstRoot)

	if err != nil {
		return res, err
	}

	delete(astTree, compilerWrapper.ContractPath)
	depAsts := astTree

	return ResultsAst{
		Ast:              srcAstRoot,
		DepAst:           depAsts,
		Aliases:          aliasesDesc,
		Abi:              abi,
		Structs:          structs,
		Libraries:        libraries,
		StateProps:       stateProps,
		MainContractName: mainContractName,
	}, nil
}

func (compilerWrapper *CompilerWrapper) collectResultsAsm(outPathAsm string) (ResultsAsm, error) {
	var res ResultsAsm

	fileAsm, err := os.Open(outPathAsm)
	if err != nil {
		return res, err
	}

	defer func() {
		if err = fileAsm.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	contentAsm, err := io.ReadAll(fileAsm)
	if err != nil {
		return res, err
	}

	var asmTree map[string]interface{}
	json.Unmarshal(contentAsm, &asmTree)

	var sources []string
	for _, source := range asmTree["sources"].([]interface{}) {
		sources = append(sources, source.(string))
	}
	sourcesFullpath, err := getSourcesFullpath(sources)
	if err != nil {
		return res, err
	}

	var asmItems []map[string]interface{}
	for _, output := range asmTree["output"].([]interface{}) {
		output := output.(map[string]interface{})

		if !compilerWrapper.Debug {
			opcode := output["opcode"].(string)
			hex := output["hex"].(string)
			asmItems = append(asmItems, map[string]interface{}{"opcode": opcode, "hex": hex})
		}

		match := reSubMatchMap(SOURCE_REGEXP, output["src"].(string))
		if len(match) > 0 {
			fileIdx, err := strconv.Atoi(match["fileIndex"])
			if err != nil {
				return res, err
			}

			var debugTag string
			tagStr, ok := match["tagStr"]
			if ok {
				if match, _ := regexp.MatchString(`\w+\.\w+:0`, tagStr); match == true {
					debugTag = DebugModeTag["FUNC_START"]
				} else if match, _ := regexp.MatchString(`\w+\.\w+:1`, tagStr); match == true {
					debugTag = DebugModeTag["FUNC_END"]
				} else if match, _ := regexp.MatchString(`loop:0`, tagStr); match == true {
					debugTag = DebugModeTag["LOOP_START"]
				}
			}

			pos := make(map[string]interface{})
			if fileIdx != -1 && len(sources) > fileIdx {
				pos["file"] = sourcesFullpath[fileIdx]

				line, err := strconv.Atoi(match["line"])
				if err != nil {
					return res, err
				}
				endLine, err := strconv.Atoi(match["endLine"])
				if err != nil {
					return res, err
				}
				column, err := strconv.Atoi(match["col"])
				if err != nil {
					return res, err
				}
				endColumn, err := strconv.Atoi(match["endCol"])
				if err != nil {
					return res, err
				}
				pos["line"] = line
				pos["endLine"] = endLine
				pos["column"] = column
				pos["endColumn"] = endColumn
			}

			asmItem := make(map[string]interface{})
			asmItem["opcode"] = output["opcode"]
			asmItem["hex"] = output["hex"]
			asmItem["stack"] = output["stack"]
			asmItem["pos"] = pos
			asmItem["debugTag"] = debugTag
			asmItems = append(asmItems, asmItem)
		}
	}

	var autoTypedVars []map[string]interface{}
	if compilerWrapper.Debug {
		for _, item := range asmTree["autoTypedVars"].([]interface{}) {
			item := item.(map[string]interface{})

			match := reSubMatchMap(SOURCE_REGEXP, item["src"].(string))
			if len(match) > 0 {
				fileIdx, err := strconv.Atoi(match["fileIndex"])
				if err != nil {
					return res, err
				}

				pos := make(map[string]interface{})
				if len(sources) > fileIdx {
					s := sources[fileIdx]

					var posFile string
					if s != "stdin" && s != "std" {
						posFile, _ = filepath.Abs(s)
					} else {
						posFile = "std"
					}
					pos["file"] = posFile

					line, err := strconv.Atoi(match["line"])
					if err != nil {
						return res, err
					}
					endLine, err := strconv.Atoi(match["endLine"])
					if err != nil {
						return res, err
					}
					column, err := strconv.Atoi(match["col"])
					if err != nil {
						return res, err
					}
					endColumn, err := strconv.Atoi(match["endCol"])
					if err != nil {
						return res, err
					}
					pos["line"] = line
					pos["endLine"] = endLine
					pos["column"] = column
					pos["endColumn"] = endColumn

					autoTypedVars = append(autoTypedVars, pos)
				}

			}
		}
	}

	var rawAsmSb strings.Builder
	var rawHexSb strings.Builder
	for i, item := range asmItems {
		rawAsmSb.WriteString(item["opcode"].(string))
		if !(i == len(asmItems)-1) {
			rawAsmSb.WriteString(" ")
		}

		rawHexSb.WriteString(item["hex"].(string))
	}

	return ResultsAsm{
		Asm:           asmItems,
		AsmTree:       asmTree,
		AutoTypedVars: autoTypedVars,
		AsmRaw:        rawAsmSb.String(),
		HexRaw:        rawHexSb.String(),
	}, nil
}

func (compilerWrapper *CompilerWrapper) getAstStructDeclarations(astTree *map[string]interface{}) []StructEntity {
	res := make([]StructEntity, 0)

	for _, srcElem := range *astTree {
		srcElem := srcElem.(map[string]interface{})

		for _, structElem := range srcElem["structs"].([]interface{}) {
			structElem := structElem.(map[string]interface{})

			name := structElem["name"].(string)

			var params []ParamEntity
			for _, field := range structElem["fields"].([]interface{}) {
				field := field.(map[string]interface{})
				pName := field["name"].(string)
				pType := field["type"].(string)
				params = append(params, ParamEntity{ // b == Student{"Bob", 0}
					Name: pName,
					Type: pType,
				})
			}

			var entity StructEntity

			entity.Name = name
			entity.Params = params

			res = append(res, entity)
		}
	}

	return res
}

func (compilerWrapper *CompilerWrapper) getAstLibraryDeclarations(astTree *map[string]interface{}) []LibraryEntity {
	res := make([]LibraryEntity, 0)

	for _, srcElem := range *astTree {
		srcElem := srcElem.(map[string]interface{})

		for _, contractElem := range srcElem["contracts"].([]interface{}) {
			contractElem := contractElem.(map[string]interface{})

			if contractElem["nodeType"] != "Library" {
				continue
			}

			name := contractElem["name"].(string)

			params := make([]ParamEntity, 0)
			val, present := contractElem["constructor"]
			if present && val != nil {
				constructor := contractElem["constructor"].(map[string]interface{})
				for _, param := range constructor["params"].([]interface{}) {
					param := param.(map[string]interface{})
					pName := "ctor." + param["name"].(string)
					pType := param["type"].(string)
					params = append(params, ParamEntity{Name: pName, Type: pType})
				}
			} else {
				for _, property := range contractElem["properties"].([]interface{}) {
					property := property.(map[string]interface{})
					pName := property["name"].(string)
					pType := property["type"].(string)
					params = append(params, ParamEntity{Name: pName, Type: pType})
				}
			}

			properties := make([]ParamEntity, 0)
			for _, property := range contractElem["properties"].([]interface{}) {
				property := property.(map[string]interface{})
				pName := property["name"].(string)
				pType := property["type"].(string)
				properties = append(properties, ParamEntity{Name: pName, Type: pType})
			}

			res = append(res, LibraryEntity{
				Name:       name,
				Params:     params,
				Properties: properties,
			})
		}
	}

	return res
}

func (compilerWrapper *CompilerWrapper) getAliases(astTree *map[string]interface{}) []AliasEntity {
	res := make([]AliasEntity, 0)

	for _, srcElem := range *astTree {
		srcElem := srcElem.(map[string]interface{})

		for _, aliasElem := range srcElem["alias"].([]interface{}) {
			aliasElem := aliasElem.(map[string]interface{})
			res = append(res, AliasEntity{Name: aliasElem["alias"].(string), Type: aliasElem["type"].(string)})
		}
	}

	return res
}

func (compilerWrapper *CompilerWrapper) getStateProps(srcAstRoot *map[string]interface{}) ([]StateEntity, error) {

	stateProps := make([]StateEntity, 0)

	contracts := (*srcAstRoot)["contracts"].([]interface{})

	if contracts[len(contracts)-1] == nil {
		return stateProps, errors.New("no contract found in ast")
	}
	mainContract := contracts[len(contracts)-1].(map[string]interface{})

	for _, property := range mainContract["properties"].([]interface{}) {
		property := property.(map[string]interface{})

		if property["state"].(bool) {
			n := property["name"].(string)
			t := property["type"].(string)
			stateProps = append(stateProps, ParamEntity{Name: n, Type: t})
		}
	}
	return stateProps, nil

}

func (compilerWrapper *CompilerWrapper) getStaticIntConstDeclarations(astTree *map[string]interface{}) map[string]*big.Int {
	res := make(map[string]*big.Int)

	for _, srcElem := range *astTree {
		srcElem := srcElem.(map[string]interface{})

		for _, contractElem := range srcElem["contracts"].([]interface{}) {
			contractElem := contractElem.(map[string]interface{})

			contractName := contractElem["name"].(string)
			for _, staticElem := range contractElem["statics"].([]interface{}) {
				staticElem := staticElem.(map[string]interface{})

				isConst := staticElem["const"].(bool)
				exprElem := staticElem["expr"].(map[string]interface{})
				if !isConst || exprElem["nodeType"].(string) != "IntLiteral" {
					continue
				}

				key := fmt.Sprintf("%s.%s", contractName, staticElem["name"].(string))
				valueString := fmt.Sprintf("%f", exprElem["value"].(float64)) // TODO: What if huge integer?
				value := new(big.Int)
				value, _ = value.SetString(valueString, 10)

				res[key] = value
			}
		}
	}

	return res
}

func (compilerWrapper *CompilerWrapper) getAbiDeclaration(srcAstRoot *map[string]interface{},
	aliases map[string]string,
	staticIntConsts *map[string]*big.Int) (string, []ABIEntity) {
	contracts := (*srcAstRoot)["contracts"].([]interface{})

	if contracts[len(contracts)-1] == nil {
		return "", nil
	}
	mainContract := contracts[len(contracts)-1].(map[string]interface{})

	mainContractName := mainContract["name"].(string)
	constructor := compilerWrapper.getConstructorDeclaration(mainContract)

	declarations := compilerWrapper.getPublicFunctionDeclarations(mainContract)
	declarations = append(declarations, constructor)
	for _, declaration := range declarations {

		params := declaration.Params
		for _, param := range params {
			resolvedParamType := compilerWrapper.resolveAbiParamType(mainContractName,
				param.Type,
				aliases,
				staticIntConsts)
			param.Type = resolvedParamType
		}

	}

	return mainContractName, declarations
}

// Extract constructor declaration from the compiler produced AST.
func (compilerWrapper *CompilerWrapper) getConstructorDeclaration(contractTree map[string]interface{}) ABIEntity {
	params := make([]ParamEntity, 0)
	if contractTree["constructor"] != nil {
		// Explicit constructor.
		constructor := contractTree["constructor"].(map[string]interface{})
		for _, param := range constructor["params"].([]interface{}) {
			param := param.(map[string]interface{})
			pName := param["name"].(string)
			pType := param["type"].(string)
			params = append(params, ParamEntity{Name: pName, Type: pType})
		}
	} else if contractTree["properties"] != nil {
		// Implicit constructor.
		properties := contractTree["properties"].([]interface{})
		for _, prop := range properties {
			prop := prop.(map[string]interface{})
			pName := strings.ReplaceAll(prop["name"].(string), "this.", "")
			pType := prop["type"].(string)
			params = append(params, ParamEntity{Name: pName, Type: pType})
		}
	}

	return ABIEntity{
		Type:   CONSTRUCTOR,
		Name:   "constructor",
		Params: params,
	}
}

// Extract public function declarations from the compiler produced AST.
func (compilerWrapper *CompilerWrapper) getPublicFunctionDeclarations(contractTree map[string]interface{}) []ABIEntity {
	res := make([]ABIEntity, 0)
	pubFuncIdx := 0

	functions := contractTree["functions"].([]interface{})
	for _, function := range functions {
		function := function.(map[string]interface{})
		visibility := function["visibility"].(string)
		name := function["name"].(string)
		nodeType := function["nodeType"].(string)
		if visibility == "Public" {

			var params []ParamEntity
			for _, param := range function["params"].([]interface{}) {
				param := param.(map[string]interface{})
				pName := param["name"].(string)
				pType := param["type"].(string)
				params = append(params, ParamEntity{Name: pName, Type: pType})
			}

			if nodeType != "Constructor" {
				res = append(res, ABIEntity{Name: name, Type: FUNCTION, Params: params, Index: pubFuncIdx})
				pubFuncIdx += 1
			}
		}

	}

	return res
}

// Resolve types of function parameters.
// This includes resolving type aliases and static integer constants in array parameter definitions.
func (compilerWrapper *CompilerWrapper) resolveAbiParamType(contractName string,
	typeStr string,
	aliases map[string]string,
	staticIntConsts *map[string]*big.Int) string {

	if IsArrayType(typeStr) {
		return compilerWrapper.resolveArrayTypeStaticIntConsts(contractName, typeStr, staticIntConsts)
	} else {
		return ResolveType(typeStr, aliases)
	}
}

// Resolves array declaration string with static constants as sizes.
// e.g. 'int[N][2]' -> 'int[5][2]'
func (compilerWrapper *CompilerWrapper) resolveArrayTypeStaticIntConsts(contractName string,
	typeStr string,
	staticIntConsts *map[string]*big.Int) string {
	typeName, arraySizes := FactorizeArrayTypeString(typeStr)

	var sizes []string
	for _, sizeString := range arraySizes {
		// Check if string is number.
		if _, err := strconv.Atoi(sizeString); err == nil {
			sizes = append(sizes, sizeString)
		} else {
			var key string
			if strings.Contains(sizeString, ".") {
				key = sizeString
			} else {
				key = fmt.Sprintf("%s.[%s]", contractName, sizeString) // TODO
			}
			sizes = append(sizes, (*staticIntConsts)[key].String())
		}
	}

	return ToLiteralArrayTypeStr(typeName, sizes)
}

func (cocompilerWrapper *CompilerWrapper) getSourceFilePrefix(contractPath string) string {
	base := filepath.Base(contractPath)
	return strings.Split(base, ".")[0]
}

func (compilerWrapper *CompilerWrapper) assembleCompilerCommand(contractPathAbs string) string {
	// Aseemble command for compiling the sCrypt contract file, passed via contractPathAbs.
	// If contractPathAbs is an empty string, then assume source code will be passed via stdin.
	// TODO: Should this return a string or a slice with the command parts as elements?
	var cmdBuff strings.Builder

	cmdBuff.WriteString(compilerWrapper.CompilerBin)
	cmdBuff.WriteString(" compile ")
	cmdBuff.WriteString("--asm ")
	cmdBuff.WriteString("--ast ")
	cmdBuff.WriteString("--hex ")

	if compilerWrapper.Debug {
		cmdBuff.WriteString("--debug ")
	}

	if compilerWrapper.Optimize {
		cmdBuff.WriteString("--optimize ")
	}
	cmdBuff.WriteString("-r ")
	cmdBuff.WriteString("-o ")
	absOutDir, _ := filepath.Abs(compilerWrapper.OutDir)
	cmdBuff.WriteString(absOutDir)
	if compilerWrapper.CmdArgs != "" {
		cmdBuff.WriteString(" ")
		cmdBuff.WriteString(compilerWrapper.CmdArgs)
	}
	if contractPathAbs != "" {
		cmdBuff.WriteString(" ")
		cmdBuff.WriteString(contractPathAbs)
	}

	return cmdBuff.String()
}

func FindCompiler() (string, error) {
	var compiler string

	var pathSuffix string
	if runtime.GOOS == "linux" {
		pathSuffix = "compiler/scryptc/linux/scryptc"
	} else if runtime.GOOS == "windows" {
		pathSuffix = "compiler/scryptc/win32/scryptc.exe"
	} else if runtime.GOOS == "darwin" {
		pathSuffix = "compiler/scryptc/mac/scryptc"
	}

	compiler = searchKnownCompilerLocations(pathSuffix)

	if compiler == "" {
		return "", errors.New("Couldn't locate compiler binary.")
	}
	return compiler, nil
}

func searchKnownCompilerLocations(pathSuffix string) string {
	res := findCompilerLocal(pathSuffix)
	if res != "" {
		return res
	}

	res = findCompilerPATH(pathSuffix)
	if res != "" {
		return res
	}

	res = findCompilerVSCode(pathSuffix)
	if res != "" {
		return res
	}

	return ""
}

func findCompilerLocal(pathSuffix string) string {
	path := filepath.Join("./", pathSuffix)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

func findCompilerPATH(pathSuffix string) string {
	path, err := exec.LookPath("scryptc")
	if err == nil {
		return path
	}
	return ""
}

func findCompilerVSCode(pathSuffix string) string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	VSCodeFolders := [2]string{".vscode-oss", ".vscode"}
	for _, VSCodeFolder := range VSCodeFolders {
		VSCodePath := filepath.Join(homeDir, VSCodeFolder)

		if fileInfoVSCodePath, err := os.Stat(VSCodePath); err == nil {
			if fileInfoVSCodePath.IsDir() {
				extensionsDir := filepath.Join(VSCodePath, "extensions")
				files, err := os.ReadDir(extensionsDir)

				if err != nil {
					log.Fatal(err)
				}

				extensionRes := ""
				for _, f := range files {
					match, _ := regexp.MatchString(`^bsv-scrypt\.scrypt-[0-9]\.[0-9]\.[0-9]$`, f.Name())

					if match {
						extensionRes = filepath.Join(extensionsDir, f.Name())
					}
				}

				if extensionRes != "" {
					compilerPath := filepath.Join(extensionRes, pathSuffix)
					if _, err := os.Stat(compilerPath); err == nil {
						return compilerPath
					}
				}
			}
		}

	}

	return ""
}

func getSourcesFullpath(sources []string) ([]string, error) {
	var res []string

	for _, source := range sources {
		if source != "stdin" && source != "std" {
			source, err := filepath.Abs(source)
			if err != nil {
				return nil, err
			}
			res = append(res, source)
		} else {
			res = append(res, "std")
		}
	}

	return res, nil
}
