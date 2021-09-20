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
            compilerBin: compilerBin,
            outDir: "./out",
            hexOut: true,
            debug: true,
            stack: true,
            optimize: false,
            cmdArgs: "",
            cwd: "./",
        }
    _, err = compilerWrapper.CompileContractFile("./test/res/p2pkh.scrypt")
    if err != nil {
        log.Fatal(err)
    }

}
