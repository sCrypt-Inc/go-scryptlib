package scryptlib


import (
    "testing"
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

    lockingScript, err := contractP2PKH.GetLockingScript()
    assert.NoError(t, err)
    lockingScriptHex := hex.EncodeToString(*lockingScript)
    err = tx.From(
        "a3865bd4351665c7531a4311f250c1eac5d6775da5ced72b4b83cfee625b6947", // Random TXID
        0,
        lockingScriptHex,
        5000)
    assert.NoError(t, err)

    var shf sighash.Flag = sighash.AllForkID
    sh, err := tx.CalcInputSignatureHash(0, shf)
    assert.NoError(t, err)
	sig, err := priv.Sign(sh)
    assert.NoError(t, err)
    //sigBytes := sig.Serialise()
    //assert.NoError(t, err)
    //sig, err := NewSigFromDECBytes(sigBytes, shf)
    //assert.NoError(t, err)

    unlockParams := map[string]ScryptType {
        "sig": Sig{sig, shf},
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

func TestContractStateCounter(t *testing.T) {
    compilerResult, err := compilerWrapper.CompileContractFile("./test/res/statecounter.scrypt")
    assert.NoError(t, err)

    desc, err := compilerResult.ToDescWSourceMap()
    assert.NoError(t, err)

    contractStateCounter, err := NewContractFromDesc(desc)
    assert.NoError(t, err)

    constructorParams := map[string]ScryptType {
        "counter": Int{big.NewInt(0)},
    }
    err = contractStateCounter.SetConstructorParams(constructorParams)
    assert.NoError(t, err)

    prevLockingScript, err := contractStateCounter.GetLockingScript()
    assert.NoError(t, err)
    prevLockingScriptHex := hex.EncodeToString(*prevLockingScript)

    // Increment counter for next locking script
    err = contractStateCounter.UpdateStateVariable("counter", Int{big.NewInt(1)})
    assert.NoError(t, err)
    currLockingScript, err := contractStateCounter.GetLockingScript()
    assert.NoError(t, err)

    // Construct TX to derive preimage, which will get used as an contract call input.
    tx := bt.NewTx()
    err = tx.From(
        "a477ff6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458", // Random TXID
        0,
        prevLockingScriptHex,
        5000)
    assert.NoError(t, err)
    currOutput := bt.Output{
        Satoshis:      4800,
        LockingScript: currLockingScript,
    }
    tx.AddOutput(&currOutput)

    preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
    assert.NoError(t, err)

    unlockParams := map[string]ScryptType {
        "txPreimage":  SigHashPreimage{preimage},
        "amount":      Int{big.NewInt(4800)},
    }
    err = contractStateCounter.SetPublicFunctionParams("unlock", unlockParams)
    assert.NoError(t, err)

    executionContext := ExecutionContext{
        Tx:             tx,
        InputIdx:       0,
        Flags:          scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
    }

    contractStateCounter.SetExecutionContext(executionContext)

    success, err := contractStateCounter.EvaluatePublicFunction("unlock")
    assert.NoError(t, err)
    assert.Equal(t, true, success)

    // Wrong increment:
    err = contractStateCounter.UpdateStateVariable("counter", Int{big.NewInt(2)})
    assert.NoError(t, err)
    currLockingScript, err = contractStateCounter.GetLockingScript()
    assert.NoError(t, err)
    tx = bt.NewTx()
    err = tx.From(
        "a477ff6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458", // Random TXID
        0,
        prevLockingScriptHex,
        5000)
    assert.NoError(t, err)
    currOutput = bt.Output{
        Satoshis:      4800,
        LockingScript: currLockingScript,
    }
    tx.AddOutput(&currOutput)

    preimage, err = tx.CalcInputPreimage(0, sighash.AllForkID)
    assert.NoError(t, err)

    unlockParams = map[string]ScryptType {
        "txPreimage":  SigHashPreimage{preimage},
        "amount":      Int{big.NewInt(4800)},
    }
    err = contractStateCounter.SetPublicFunctionParams("unlock", unlockParams)
    assert.NoError(t, err)

    executionContext = ExecutionContext{
        Tx:             tx,
        InputIdx:       0,
        Flags:          scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
    }

    contractStateCounter.SetExecutionContext(executionContext)
    success, err = contractStateCounter.EvaluatePublicFunction("unlock")
    assert.Error(t, err)
    assert.Equal(t, false, success)

    // Wrong amount:
    err = contractStateCounter.UpdateStateVariable("counter", Int{big.NewInt(1)})
    assert.NoError(t, err)
    unlockParams = map[string]ScryptType {
        "txPreimage":  SigHashPreimage{preimage},
        "amount":      Int{big.NewInt(4799)},
    }
    err = contractStateCounter.SetPublicFunctionParams("unlock", unlockParams)
    success, err = contractStateCounter.EvaluatePublicFunction("unlock")
    assert.Error(t, err)
    assert.Equal(t, false, success)

}

func TestContractDynamicArrayDemo(t *testing.T) {
    compilerResult, err := compilerWrapper.CompileContractFile("./test/res/dynamicArrayDemo.scrypt")
    assert.NoError(t, err)

    desc, err := compilerResult.ToDescWSourceMap()
    assert.NoError(t, err)

    contractDemo, err := NewContractFromDesc(desc)
    assert.NoError(t, err)

    testParams := map[string]ScryptType {
        "_x": Int{big.NewInt(0)},
    }
    err = contractDemo.SetPublicFunctionParams("test", testParams)
    assert.NoError(t, err)

    success, err := contractDemo.EvaluatePublicFunction("test")
    assert.NoError(t, err)
    assert.Equal(t, true, success)
}
