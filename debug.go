package scryptlib

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/thoas/go-funk"
)

type TxContext struct {
	Hex           string `json:"hex"`
	InputIndex    int    `json:"inputIndex"`
	InputSatoshis int    `json:"inputSatoshis"`
	OpReturn      string `json:"opReturn"`
	OpReturnHex   string `json:"opReturnHex"`
}

func (txContext TxContext) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{}, 0)
	m["hex"] = txContext.Hex
	m["inputIndex"] = txContext.InputIndex
	m["inputSatoshis"] = txContext.InputSatoshis

	if len(strings.TrimSpace(txContext.OpReturnHex)) > 0 {
		m["opReturnHex"] = txContext.OpReturnHex
	}

	if len(strings.TrimSpace(txContext.OpReturn)) > 0 {
		m["opReturn"] = txContext.OpReturn
	}

	return json.MarshalIndent(m, "", "  ")
}

type DebugConfiguration struct {
	Request                string       `json:"request"`
	Type                   string       `json:"type"`
	InternalConsoleOptions string       `json:"internalConsoleOptions"`
	Name                   string       `json:"name"`
	Program                string       `json:"program"`
	ConstructorArgs        []ScryptType `json:"constructorArgs"`
	PubFunc                string       `json:"pubFunc"`
	PubFuncArgs            []ScryptType `json:"pubFuncArgs"`
	TxContext              *TxContext   `json:"txContext"`
}

type DebugLaunch struct {
	Version        string               `json:"version"`
	Configurations []DebugConfiguration `json:"configurations"`
}

func (contract *Contract) genLaunchConfigFile() (string, error) {

	constructorArgs := funk.Map(contract.constructorParams, func(param functionParam) ScryptType {
		return param.Value
	})

	pubFunc := contract.executedPubFunc

	if isStringEmpty(pubFunc) {
		panic(errors.New("pubFunc not specified, call `contract.genLaunchConfig()` after `contract.EvaluatePublicFunction(pubFunc)` is called"))
	}

	publicFunction, ok := contract.publicFunctions[pubFunc]

	if !ok {
		panic(fmt.Errorf("no pubFunc [%s] found", pubFunc))
	}

	pubFuncArgs := funk.Map(publicFunction.Params, func(param functionParam) ScryptType {
		return param.Value
	})

	name := "Debug " + contract.name

	program := contract.file

	debugConfig := DebugConfiguration{
		Type:                   "scrypt",
		Request:                "launch",
		InternalConsoleOptions: "openOnSessionStart",
		Name:                   name,
		Program:                program,
		ConstructorArgs:        constructorArgs.([]ScryptType),
		PubFunc:                pubFunc,
		PubFuncArgs:            pubFuncArgs.([]ScryptType),
	}

	if contract.IsExecutionContextSet() {

		txContext, err := contract.GetTxContext()

		if err != nil {
			panic(err)
		}

		debugConfig.TxContext = &txContext

	} else {
		debugConfig.TxContext = nil
	}

	configurations := make([]DebugConfiguration, 0)

	configurations = append(configurations, debugConfig)

	launch := DebugLaunch{
		Version:        "0.2.0",
		Configurations: configurations,
	}

	launchJSON, err := json.MarshalIndent(launch, "", "  ")

	if err != nil {
		return "", err
	}

	filename := fmt.Sprintf("%s-launch.json", name)

	dname, err := os.MkdirTemp("", "sCrypt.")

	if err != nil {
		return "", err
	}

	fname := filepath.Join(dname, filename)

	err = os.WriteFile(fname, launchJSON, 0666)

	u := &url.URL{
		Scheme: "file",
		Path:   fname,
	}

	return u.String(), err
}

func (contract *Contract) genLaunchConfig() string {

	file, err := contract.genLaunchConfigFile()

	if err != nil {
		fmt.Println(err)
		return ""
	}
	url := fmt.Sprintf("\t[Launch Debugger](%s)\n", strings.Replace(file, "file:", "scryptlaunch:", 1))
	return url
}
