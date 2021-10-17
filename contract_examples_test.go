package scryptlib


import (
    "testing"
    "context"
    "math/big"
    "encoding/hex"

    "github.com/stretchr/testify/assert"

    "github.com/libsv/go-bk/crypto"
    "github.com/libsv/go-bk/wif"
    "github.com/libsv/go-bt/v2"
    "github.com/libsv/go-bt/v2/sighash"
    "github.com/libsv/go-bt/v2/bscript/interpreter/scriptflag"
)


func TestContractDemo(t *testing.T) {
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

    success, err := contractDemo.EvaluatePublicFunction("add")
    assert.NoError(t, err)
    assert.Equal(t, true, success)

    subCorrect := Int{big.NewInt(3)}
    subParams := map[string]ScryptType {
        "z": subCorrect,
    }
    err = contractDemo.SetPublicFunctionParams("sub", subParams)
    assert.NoError(t, err)

    success, err = contractDemo.EvaluatePublicFunction("sub")
    assert.NoError(t, err)
    assert.Equal(t, true, success)
}

func TestContractP2PKH(t *testing.T) {
    compilerResult, err := compilerWrapper.CompileContractFile("./test/res/p2pkh.scrypt")
    assert.NoError(t, err)

    desc, err := compilerResult.ToDescWSourceMap()
    assert.NoError(t, err)

    contractP2PKH, err := NewContractFromDesc(desc)
    assert.NoError(t, err)

    wif_key, err := wif.DecodeWIF("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
    assert.NoError(t, err)
    priv := wif_key.PrivKey
    addr := crypto.Hash160(wif_key.SerialisePubKey())

    pubKeyHash := Ripemd160{addr}
    constructorParams := map[string]ScryptType {
        "pubKeyHash": pubKeyHash,
    }
    err = contractP2PKH.SetConstructorParams(constructorParams)
    assert.NoError(t, err)

    tx := bt.NewTx()
    assert.NotNil(t, tx)

    lockingScript, err := contractP2PKH.GetLockingScript()
    assert.NoError(t, err)
    lockingScriptHex := hex.EncodeToString(*lockingScript)
    err = tx.From(
        "a3865bd4351665c7531a4311f250c1eac5d6775da5ced72b4b83cfee625b6947", // Random TXID
        0,
        lockingScriptHex,
        5000)
    assert.NoError(t, err)

    assert.NoError(t, err)
    localSigner := bt.LocalSigner{priv}

    var shf sighash.Flag = sighash.AllForkID
    _, sigBytes, err := localSigner.Sign(context.Background(), tx, 0, shf)
    assert.NoError(t, err)
    sig, err := NewSigFromDECBytes(sigBytes, shf)
    assert.NoError(t, err)

    unlockParams := map[string]ScryptType {
        "sig": sig,
        "pubKey": PubKey{priv.PubKey()},
    }
    err = contractP2PKH.SetPublicFunctionParams("unlock", unlockParams)
    assert.NoError(t, err)

    executionContext := ExecutionContext{
        Tx:             tx,
        InputIdx:       0,
        Flags:          scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
    }

    contractP2PKH.SetExecutionContext(executionContext)

    success, err := contractP2PKH.EvaluatePublicFunction("unlock")
    assert.NoError(t, err)
    assert.Equal(t, true, success)
}
