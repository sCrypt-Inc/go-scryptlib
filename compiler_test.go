package scryptlib


import (
    "testing"
    "log"
)


func TestCompiler0(t *testing.T) {
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

    compilerResult, err := compilerWrapper.CompileContractFile("./test/res/p2pkh.scrypt")
    if err != nil {
        log.Fatal(err)
    }

    _, err = compilerResult.ToDescWSourceMap()
    if err != nil {
        log.Fatal(err)
    }


}
