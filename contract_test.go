package scryptlib


import (
    "testing"
    "math/big"

    "github.com/stretchr/testify/assert"
)

func TestContractParamCheck(t *testing.T) {
    compilerBin, err := FindCompiler()
    assert.NoError(t, err)

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
    assert.NoError(t, err)

    desc, err := compilerResult.ToDescWSourceMap()
    assert.NoError(t, err)

    contractDemo, err := NewContractFromDesc(desc)
    assert.NoError(t, err)

    x := Int{big.NewInt(7)}
    y := Int{big.NewInt(4)}
    constructorParams := map[string]ScryptType {
        "x": x,
        "y": y,
    }

    err = contractDemo.SetConstructorParams(constructorParams)
    assert.NoError(t, err)

    sumCorrect := Int{big.NewInt(11)}
    addParams := map[string]ScryptType {
        "z": sumCorrect,
    }
    err = contractDemo.SetPublicFunctionParams("add", addParams)
    assert.NoError(t, err)

    success, err := contractDemo.VerifyPublicFunction("add")
    assert.NoError(t, err)
    assert.Equal(t, true, success)

}
