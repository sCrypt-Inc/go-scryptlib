package scryptlib


import (
    "testing"
    "log"
    "math/big"

    //"github.com/stretchr/testify/assert"
)

func TestContractParamCheck(t *testing.T) {
    compilerBin, err := FindCompiler()
    if err != nil {
        log.Fatal(err)
    }

    compilerWrapper := CompilerWrapper {
            CompilerBin: compilerBin,
            OutDir: "./out",
            HexOut: true,
            Debug: true,
            Desc: true,
            Stack: true,
            Optimize: false,
            CmdArgs: "",
            Cwd: "./",
        }

    compilerResult, err := compilerWrapper.CompileContractFile("./test/res/demo.scrypt")
    if err != nil {
        log.Fatal(err)
    }

    desc, err := compilerResult.ToDescWSourceMap()
    if err != nil {
        log.Fatal(err)
    }

    contractDemo, err := NewContractFromDesc(desc)
    if err != nil {
        log.Fatal(err)
    }

    //fmt.Println(contractDemo.constructorParams)
    //fmt.Println(contractDemo.publicFunctions)

    x := Int{big.NewInt(1234238)}
    y := Int{big.NewInt(14337238)}
    constructorParams := map[string]ScryptType {
        "x": x,
        "y": y,
    }

    err = contractDemo.SetConstructorParams(constructorParams)
    if err != nil {
        log.Fatal(err)
    }

    sumCorrect := Int{big.NewInt(15571476)}
    addParams := map[string]ScryptType {
        "z": sumCorrect,
    }
    err = contractDemo.SetPublicFunctionParams("add", addParams)
    if err != nil {
        log.Fatal(err)
    }

    //diffCorrect := Int{big.NewInt(-13103000)}




}
