package scryptlib

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/libsv/go-bk/crypto"
	"github.com/libsv/go-bk/wif"
	"github.com/sCrypt-Inc/go-bt/v2"
	"github.com/sCrypt-Inc/go-bt/v2/bscript/interpreter/scriptflag"
	"github.com/sCrypt-Inc/go-bt/v2/sighash"
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
	constructorParams := map[string]ScryptType{
		"x": x,
		"y": y,
	}

	err = contractDemo.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	sumCorrect := Int{big.NewInt(11)}
	addParams := map[string]ScryptType{
		"z": sumCorrect,
	}
	err = contractDemo.SetPublicFunctionParams("add", addParams)
	assert.NoError(t, err)

	success, err := contractDemo.EvaluatePublicFunction("add")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

	subCorrect := Int{big.NewInt(3)}
	subParams := map[string]ScryptType{
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
	addr := crypto.Hash160(priv.PubKey().SerialiseCompressed())

	pubKeyHash := Ripemd160{addr}
	constructorParams := map[string]ScryptType{
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

	unlockParams := map[string]ScryptType{
		"sig":    Sig{sig, shf},
		"pubKey": PubKey{priv.PubKey()},
	}
	err = contractP2PKH.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	contractP2PKH.SetExecutionContext(executionContext)

	success, err := contractP2PKH.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

}

func TestContractCounter(t *testing.T) {
	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/counter.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	counter, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{}
	err = counter.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	counter.SetDataPartInASM("00")

	lockingScript, err := counter.GetLockingScript()
	assert.NoError(t, err)

	// Construct TX to derive preimage, which will get used as an contract call input.
	tx := bt.NewTx()
	err = tx.From(
		"a477ff6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458", // Random TXID
		0,
		hex.EncodeToString(*lockingScript),
		5000)
	assert.NoError(t, err)

	//Increment counter for next locking script

	newLockingScript, err := counter.GetNewLockingScript("0101")

	assert.NoError(t, err)
	currOutput := bt.Output{
		Satoshis:      4800,
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"txPreimage": SigHashPreimage{preimage},
		"amount":     Int{big.NewInt(4800)},
	}
	err = counter.SetPublicFunctionParams("increment", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	counter.SetExecutionContext(executionContext)

	success, err := counter.EvaluatePublicFunction("increment")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

}

func increment(t *testing.T, counter *Contract, value Int) bool {
	prevLockingScript, err := counter.GetLockingScript()
	assert.NoError(t, err)
	prevLockingScriptHex := hex.EncodeToString(*prevLockingScript)

	// Increment counter for next locking script

	states := map[string]ScryptType{
		"counter": value,
	}

	newLockingScript, err := counter.getNewStateScript(states)
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
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"txPreimage": SigHashPreimage{preimage},
		"amount":     Int{big.NewInt(4800)},
	}
	err = counter.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	counter.SetExecutionContext(executionContext)

	success, _ := counter.EvaluatePublicFunction("unlock")

	return success

}

func TestContractStateCounter(t *testing.T) {
	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/statecounter.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	contractStateCounter, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{
		"counter": Int{big.NewInt(0)},
	}
	err = contractStateCounter.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	assert.Equal(t, true, increment(t, &contractStateCounter, Int{big.NewInt(1)}))

	//update state after EvaluatePublicFunction success
	contractStateCounter.UpdateStateVariable("counter", Int{big.NewInt(1)})

	assert.Equal(t, true, increment(t, &contractStateCounter, Int{big.NewInt(2)}))
	contractStateCounter.UpdateStateVariable("counter", Int{big.NewInt(2)})

	assert.Equal(t, true, increment(t, &contractStateCounter, Int{big.NewInt(3)}))
	contractStateCounter.UpdateStateVariable("counter", Int{big.NewInt(3)})

	assert.Equal(t, false, increment(t, &contractStateCounter, Int{big.NewInt(3)}))
	assert.Equal(t, true, increment(t, &contractStateCounter, Int{big.NewInt(4)}))
	contractStateCounter.UpdateStateVariable("counter", Int{big.NewInt(4)})
}

func TestContractDynamicArrayDemo(t *testing.T) {
	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/dynamicArrayDemo.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	contractDemo, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	testParams := map[string]ScryptType{
		"_x": Int{big.NewInt(0)},
	}
	err = contractDemo.SetPublicFunctionParams("test", testParams)
	assert.NoError(t, err)

	success, err := contractDemo.EvaluatePublicFunction("test")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractStateExample(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/state.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	st2, err := example.GetStructTypeTemplate("ST2")
	assert.NoError(t, err)
	st2a := Array{[]ScryptType{st2}}

	wif_key0, err := wif.DecodeWIF("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
	assert.NoError(t, err)
	priv0 := wif_key0.PrivKey

	addr := crypto.Hash160(priv0.PubKey().SerialiseCompressed())

	var shf sighash.Flag = sighash.AllForkID
	sig, err := priv0.Sign([]byte{0x01, 0x01})
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{
		"counter":     Int{big.NewInt(0)},
		"state_bytes": NewBytes([]byte{0x01, 0x01}),
		"state_bool":  Bool{true},
		"privKey":     PrivKey{priv0},
		"pubkey":      PubKey{priv0.PubKey()},
		"ripemd160":   Ripemd160{addr},
		"sha256":      NewSha256([]byte{0x00}),
		"opCodeType":  NewOpCodeType([]byte{0x00}),
		"sigHashType": NewSighHashType([]byte{0x41}),
		"sig":         Sig{sig, shf},
		"st2":         st2a,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	prevLockingScript, err := example.GetLockingScript()

	assert.NoError(t, err)
	prevLockingScriptHex := hex.EncodeToString(*prevLockingScript)

	states := map[string]ScryptType{
		"counter":     Int{big.NewInt(1)},
		"state_bytes": NewBytes([]byte{0x01, 0x01, 0x01}),
		"state_bool":  Bool{false},
		"privKey":     PrivKey{priv0},
		"pubkey":      PubKey{priv0.PubKey()},
		"ripemd160":   Ripemd160{addr},
		"sha256":      NewSha256([]byte{0x00}),
		"opCodeType":  NewOpCodeType([]byte{0x00}),
		"sigHashType": NewSighHashType([]byte{0x41}),
		"sig":         Sig{sig, shf},
		"st2":         st2a,
	}

	newLockingScript, err := example.getNewStateScript(states)

	assert.NoError(t, err)

	tx := bt.NewTx()
	err = tx.From(
		"a477ff6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458",
		0,
		prevLockingScriptHex,
		300000)
	assert.NoError(t, err)
	currOutput := bt.Output{
		Satoshis:      222222,
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"txPreimage": SigHashPreimage{preimage},
		"amount":     Int{big.NewInt(222222)},
	}
	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	example.SetExecutionContext(executionContext)
	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

	//should update state after EvaluatePublicFunction
	err = example.UpdateStateVariables(states)
	assert.NoError(t, err)
}

func TestContractToken(t *testing.T) {

	wif_key0, err := wif.DecodeWIF("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
	assert.NoError(t, err)
	priv0 := wif_key0.PrivKey

	wif_key1, err := wif.DecodeWIF("cV1Y7ARUr9Yx7BR55nTdnR7ZXNJphZtCCMBTEZBJe1hXt2kB684q")
	assert.NoError(t, err)
	priv1 := wif_key1.PrivKey

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/token.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	token, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	new_account0, err := token.GetStructTypeTemplate("Account")
	assert.NoError(t, err)
	new_account0.UpdateValue("pubKey", PubKey{priv0.PubKey()})
	new_account0.UpdateValue("balance", Int{big.NewInt(60)})
	new_account1, err := token.GetStructTypeTemplate("Account")
	assert.NoError(t, err)
	new_account1.UpdateValue("pubKey", PubKey{priv1.PubKey()})
	new_account1.UpdateValue("balance", Int{big.NewInt(40)})
	new_accounts := Array{[]ScryptType{new_account0, new_account1}}

	constructorParams := map[string]ScryptType{
		"accounts": new_accounts,
	}
	err = token.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	prevLockingScript, err := token.GetLockingScript()

	assert.NoError(t, err)
	prevLockingScriptHex := hex.EncodeToString(*prevLockingScript)

	account0, err := token.GetStructTypeTemplate("Account")
	assert.NoError(t, err)
	account0.UpdateValue("pubKey", PubKey{priv0.PubKey()})
	account0.UpdateValue("balance", Int{big.NewInt(20)})
	account1, err := token.GetStructTypeTemplate("Account")
	assert.NoError(t, err)
	account1.UpdateValue("pubKey", PubKey{priv1.PubKey()})
	account1.UpdateValue("balance", Int{big.NewInt(80)})
	accounts := Array{[]ScryptType{account0, account1}}

	states := map[string]ScryptType{
		"accounts": accounts,
	}

	newLockingScript, err := token.getNewStateScript(states)
	assert.NoError(t, err)

	tx := bt.NewTx()
	err = tx.From(
		"a477ff6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458",
		0,
		prevLockingScriptHex,
		300000)
	assert.NoError(t, err)
	currOutput := bt.Output{
		Satoshis:      222222,
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	var shf sighash.Flag = sighash.AllForkID
	sh, err := tx.CalcInputSignatureHash(0, shf)
	assert.NoError(t, err)
	senderSig, err := priv0.Sign(sh)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"sender":     PubKey{priv0.PubKey()},
		"senderSig":  Sig{senderSig, shf},
		"receiver":   PubKey{priv1.PubKey()},
		"value":      Int{big.NewInt(40)},
		"txPreimage": SigHashPreimage{preimage},
		"amount":     Int{big.NewInt(222222)},
	}
	err = token.SetPublicFunctionParams("transfer", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	token.SetExecutionContext(executionContext)
	success, err := token.EvaluatePublicFunction("transfer")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

	//should update state after EvaluatePublicFunction
	err = token.UpdateStateVariable("accounts", accounts)
	assert.NoError(t, err)
}

func TestContractNestedStructArr(t *testing.T) {

	source := `
        struct Thing {
            int someNumber;
            OtherThing[2] otherThings;
        }

        struct OtherThing {
            bytes someBytes;
            int[3] numbers;
        }

        contract NestedStructs {
            Thing thing;

            public function unlock(int[2][3] numbers, int someNumber, bytes[2] someBytes) {
                loop (2) : i {
                    auto otherThing = this.thing.otherThings[i];
                    require(otherThing.someBytes == someBytes[i]);
                    loop (3) : j {
                        require(otherThing.numbers[j] == numbers[i][j]);
                    }
                }
                require(this.thing.someNumber == someNumber);
            }
        }`

	compilerResult, err := compilerWrapper.CompileContractString(source)
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	nestedStructs, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	otherThingsVals := make([]ScryptType, 2)
	for i := 0; i < 2; i++ {
		otherThing, err := nestedStructs.GetStructTypeTemplate("OtherThing")
		assert.NoError(t, err)
		otherThing.UpdateValue("someBytes", Bytes{make([]byte, 3)})
		numVals := make([]ScryptType, 3)
		for j := 0; j < 3; j++ {
			numVals[j] = Int{big.NewInt(0)}
		}
		otherThing.UpdateValue("numbers", Array{numVals})
		otherThingsVals[i] = otherThing
	}

	thing, err := nestedStructs.GetStructTypeTemplate("Thing")
	assert.NoError(t, err)
	thing.UpdateValue("someNumber", Int{big.NewInt(123)})
	thing.UpdateValue("otherThings", Array{otherThingsVals})

	constructorParams := map[string]ScryptType{
		"thing": thing,
	}
	err = nestedStructs.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	numbers := make([]ScryptType, 2)
	bytes := make([]ScryptType, 2)
	for i := 0; i < 2; i++ {
		numVals := make([]ScryptType, 3)
		for j := 0; j < 3; j++ {
			numVals[j] = Int{big.NewInt(0)}
		}
		numbers[i] = Array{numVals}
		bytes[i] = Bytes{make([]byte, 3)}
	}

	unlockParams := map[string]ScryptType{
		"numbers":    Array{numbers},
		"someNumber": Int{big.NewInt(123)},
		"someBytes":  Array{bytes},
	}
	err = nestedStructs.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := nestedStructs.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractLibAsProperty(t *testing.T) {

	source := `
        library L {
          private int x;
        
          constructor(int a, int b) {
            this.x = a + b;
          }
          function f() : int {
            return this.x;
          }
        }
        
        
        contract Test {
          private int x;
          L l;
        
          public function unlock(int x) {
            require(this.l.f() == this.x + x);
            require(true);
          }
        }
        `
	compilerResult, err := compilerWrapper.CompileContractString(source)
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	libAsPropertyTest, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	l, err := libAsPropertyTest.GetLibraryTypeTemplate("L")
	assert.NoError(t, err)
	l.UpdateValue("a", Int{big.NewInt(1)})
	l.UpdateValue("b", Int{big.NewInt(2)})

	constructorParams := map[string]ScryptType{
		"x": Int{big.NewInt(1)},
		"l": l,
	}

	err = libAsPropertyTest.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"x": Int{big.NewInt(2)},
	}
	err = libAsPropertyTest.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := libAsPropertyTest.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

}

func TestContractLibAsPropertyWithOutConstructor(t *testing.T) {

	source := `
        library L {
          private int x;
        
          function f() : int {
            return this.x;
          }
        }

        contract Test {
          private int x;
          L l;
        
          public function unlock(int x) {
            require(this.l.f() == this.x + x);
            require(true);
          }
        }
        `
	compilerResult, err := compilerWrapper.CompileContractString(source)
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	libAsPropertyTest, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	l, err := libAsPropertyTest.GetLibraryTypeTemplate("L")
	assert.NoError(t, err)
	l.UpdateValue("x", Int{big.NewInt(2)})

	constructorParams := map[string]ScryptType{
		"x": Int{big.NewInt(1)},
		"l": l,
	}

	err = libAsPropertyTest.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"x": Int{big.NewInt(1)},
	}
	err = libAsPropertyTest.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := libAsPropertyTest.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

}

func TestContractArraySimple(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/arraysimple.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	a, err := example.GetTypeTemplate("int[2][3][1]")
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{
		"a": a,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"a": a,
	}

	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractArray(t *testing.T) {

	source := `
        contract TestArray {
          int[3] x;

          public function unlock(int[3] x) {
            require(this.x == x);
          }
        }
    `
	compilerResult, err := compilerWrapper.CompileContractString(source)
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	testArray, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	a := [3]Int{{big.NewInt(1)}, {big.NewInt(2)}, {big.NewInt(3)}}

	b := make([]ScryptType, 3)

	for i := 0; i < 3; i++ {
		b[i] = a[i]
	}

	constructorParams := map[string]ScryptType{
		"x": Array{b},
	}

	err = testArray.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"x": Array{b},
	}
	err = testArray.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := testArray.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

}

func TestLibrary1(t *testing.T) {
	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/library1.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	library1, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	_, err = library1.GetLockingScript()

	assert.NoError(t, err)

	l, err := library1.GetLibraryTypeTemplate("L")
	assert.NoError(t, err)
	l.UpdateValue("a", Int{big.NewInt(1)})
	l.UpdateValue("b", Int{big.NewInt(2)})

	l1, err := library1.GetLibraryTypeTemplate("L1")
	assert.NoError(t, err)
	l1.UpdateValue("x", Int{big.NewInt(1)})
	l1.UpdateValue("l", Array{[]ScryptType{l, l}})

	constructorParams := map[string]ScryptType{
		"x":  Int{big.NewInt(1)},
		"l1": l1,
	}

	err = library1.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"x": Int{big.NewInt(5)},
	}
	err = library1.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := library1.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestLibrary2(t *testing.T) {
	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/library2.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	library2, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	_, err = library2.GetLockingScript()

	assert.NoError(t, err)

	st, err := library2.GetStructTypeTemplate("ST")
	assert.NoError(t, err)

	st.UpdateValue("a", Array{[]ScryptType{Int{big.NewInt(4)}, Int{big.NewInt(5)}}})
	st.UpdateValue("b", Bool{false})
	st.UpdateValue("c", Bytes{[]byte{0x01, 0xef, 0x02}})
	l, err := library2.GetLibraryTypeTemplate("L")
	assert.NoError(t, err)

	l.UpdateValue("st", st)

	constructorParams := map[string]ScryptType{
		"l": l,
	}

	err = library2.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"st": st,
	}
	err = library2.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := library2.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestLibrary3(t *testing.T) {
	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/library3.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	library3, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	_, err = library3.GetLockingScript()

	assert.NoError(t, err)

	l, err := library3.GetLibraryTypeTemplate("L")
	assert.NoError(t, err)

	l.UpdateValue("a", Int{big.NewInt(1)})
	l.UpdateValue("b", Int{big.NewInt(2)})

	l1, err := library3.GetLibraryTypeTemplate("L1")
	assert.NoError(t, err)
	l1.UpdateValue("xx", l)

	constructorParams := map[string]ScryptType{
		"l1": l1,
		"x":  Int{big.NewInt(1)},
	}

	err = library3.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"x": Int{big.NewInt(2)},
	}
	err = library3.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := library3.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestLibrary4(t *testing.T) {
	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/library4.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	library3, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	_, err = library3.GetLockingScript()

	assert.NoError(t, err)

	l1, err := library3.GetLibraryTypeTemplate("L1")
	assert.NoError(t, err)
	l1.UpdateValue("a", Int{big.NewInt(1)})
	l1.UpdateValue("b", Int{big.NewInt(2)})

	st, err := library3.GetStructTypeTemplate("ST")
	assert.NoError(t, err)
	st.UpdateValue("x", Int{big.NewInt(2)})

	l2, err := library3.GetLibraryTypeTemplate("L2")
	assert.NoError(t, err)
	l2.UpdateValue("x", Array{[]ScryptType{st}})

	l3, err := library3.GetLibraryTypeTemplate("L3")
	assert.NoError(t, err)
	l3.UpdateValue("l1", l1)
	l3.UpdateValue("l2", l2)

	l4, err := library3.GetLibraryTypeTemplate("L4")
	assert.NoError(t, err)
	l4.UpdateValue("l3", l3)

	constructorParams := map[string]ScryptType{
		"l4": l4,
	}

	err = library3.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"x": Int{big.NewInt(5)},
	}
	err = library3.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := library3.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

}

func runPut(t *testing.T, hashedmap *Contract, hm HashedMap, pkh Ripemd160, balance int64) {

	data, _ := hm.RawHex()

	dataPart, _ := serializeState(data, STATE_LEN_3BYTES)

	hashedmap.SetDataPartInHex(dataPart)

	lockingScript, err := hashedmap.GetLockingScript()
	assert.NoError(t, err)

	// Construct TX to derive preimage, which will get used as an contract call input.
	tx := bt.NewTx()
	err = tx.From(
		"a477ff6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458", // Random TXID
		0,
		hex.EncodeToString(*lockingScript),
		5000)
	assert.NoError(t, err)

	hm.Set(pkh, Int{big.NewInt(int64(balance))})

	newdata, _ := hm.RawHex()

	newDataPart, _ := serializeState(newdata, STATE_LEN_3BYTES)

	newLockingScript, err := hashedmap.GetNewLockingScript(newDataPart)
	assert.NoError(t, err)
	currOutput := bt.Output{
		Satoshis:      5000,
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	key, err := hashedmap.GetStructTypeTemplate("Key")
	assert.NoError(t, err)

	key.UpdateValue("pkh", pkh)

	keyIndex, err := hm.KeyIndex(pkh)

	assert.NoError(t, err)

	key.UpdateValue("keyIndex", Int{big.NewInt(int64(keyIndex))})

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"txPreimage": SigHashPreimage{preimage},
		"balance":    Int{big.NewInt(int64(balance))},
		"key":        key,
	}
	err = hashedmap.SetPublicFunctionParams("put", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	hashedmap.SetExecutionContext(executionContext)

	success, err := hashedmap.EvaluatePublicFunction("put")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

	//update the state of the contract instance after the contract be executed
	hashedmap.SetDataPartInHex(newDataPart)
}

func runDelete(t *testing.T, hashedmap *Contract, hm HashedMap, pkh Ripemd160) {

	data, _ := hm.RawHex()

	dataPart, _ := serializeState(data, STATE_LEN_3BYTES)

	hashedmap.SetDataPartInHex(dataPart)

	lockingScript, err := hashedmap.GetLockingScript()
	assert.NoError(t, err)

	// Construct TX to derive preimage, which will get used as an contract call input.
	tx := bt.NewTx()
	err = tx.From(
		"a477ff6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458", // Random TXID
		0,
		hex.EncodeToString(*lockingScript),
		5000)
	assert.NoError(t, err)

	//save keyIndex before we delete key-value pair
	keyIndex, err := hm.KeyIndex(pkh)

	assert.NoError(t, err)

	err = hm.Delete(pkh)

	assert.NoError(t, err)

	newdata, _ := hm.RawHex()

	newDataPart, _ := serializeState(newdata, STATE_LEN_3BYTES)

	newLockingScript, err := hashedmap.GetNewLockingScript(newDataPart)
	assert.NoError(t, err)
	currOutput := bt.Output{
		Satoshis:      5000,
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	key, err := hashedmap.GetStructTypeTemplate("Key")
	assert.NoError(t, err)
	key.UpdateValue("pkh", pkh)

	key.UpdateValue("keyIndex", Int{big.NewInt(int64(keyIndex))})

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"txPreimage": SigHashPreimage{preimage},
		"key":        key,
	}

	err = hashedmap.SetPublicFunctionParams("delete", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	hashedmap.SetExecutionContext(executionContext)

	success, err := hashedmap.EvaluatePublicFunction("delete")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

	//update the state of the contract instance after the contract be executed
	hashedmap.SetDataPartInHex(newDataPart)
}

func NewPKH(wifstr string) Ripemd160 {
	wif_key, _ := wif.DecodeWIF(wifstr)
	priv := wif_key.PrivKey
	addr := crypto.Hash160(priv.PubKey().SerialiseCompressed())
	return Ripemd160{addr}
}

func TestContractHashedMap(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/hashedmap.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	hashedmap, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{}
	err = hashedmap.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	hm := NewHashedMap()

	pkh := NewPKH("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")

	balance := 11111
	runPut(t, &hashedmap, hm, pkh, int64(balance))

	// update balance
	balance = 11111111
	runPut(t, &hashedmap, hm, pkh, int64(balance))

	// PUT one more key-value pair

	pkh1 := NewPKH("cQcjHS827WgD9yu7JDEPzxcZnYMBde7yjQoiiMBDTC6hG55m4ME3")
	runPut(t, &hashedmap, hm, pkh1, 21000)

	// PUT one more key-value pair
	pkh2 := NewPKH("cQrRVKafjo7Hy4HFD8NJWUUW4h9M9deQhBu6V6YTQpUcRQvfswHJ")
	runPut(t, &hashedmap, hm, pkh2, 100000)
	runPut(t, &hashedmap, hm, pkh2, 0)

	//	PUT one more key-value pair
	pkh3 := NewPKH("cV3hHnEZekLakJc8aLohu7yq5PTjVT41mx4r6FzGRCi38sZ8c7kY")
	runPut(t, &hashedmap, hm, pkh3, 100)

	runDelete(t, &hashedmap, hm, pkh2)

}

func TestContractLibAsState1(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/LibAsState1.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	st, err := example.GetStructTypeTemplate("ST")
	assert.NoError(t, err)

	st.UpdateValue("x", Int{big.NewInt(1)})
	st.UpdateValue("c", Bool{true})
	st.UpdateValue("aa", Array{[]ScryptType{Int{big.NewInt(1)}, Int{big.NewInt(1)}, Int{big.NewInt(1)}}})

	l, err := example.GetLibraryTypeTemplate("L")
	assert.NoError(t, err)
	l.UpdateValue("x", Int{big.NewInt(1)})
	l.UpdateValue("st", st)

	constructorParams := map[string]ScryptType{
		"l": l,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	prevLockingScript, err := example.GetLockingScript()

	assert.NoError(t, err)
	prevLockingScriptHex := hex.EncodeToString(*prevLockingScript)

	newst, err := example.GetStructTypeTemplate("ST")
	assert.NoError(t, err)
	newst.UpdateValue("x", Int{big.NewInt(1)})
	newst.UpdateValue("c", Bool{false})
	newst.UpdateValue("aa", Array{[]ScryptType{Int{big.NewInt(1)}, Int{big.NewInt(1)}, Int{big.NewInt(1)}}})

	newl, err := example.GetLibraryTypeTemplate("L")
	assert.NoError(t, err)
	//when update library state, should using UpdatePropertyValue
	newl.UpdatePropertyValue("x", Int{big.NewInt(6)})
	newl.UpdatePropertyValue("st", newst)

	states := map[string]ScryptType{
		"l": newl,
	}

	newLockingScript, err := example.getNewStateScript(states)

	assert.NoError(t, err)

	tx := bt.NewTx()
	err = tx.From(
		"a477ff6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458",
		0,
		prevLockingScriptHex,
		300000)
	assert.NoError(t, err)
	currOutput := bt.Output{
		Satoshis:      300000,
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"x":        Int{big.NewInt(1)},
		"preimage": SigHashPreimage{preimage},
	}
	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	example.SetExecutionContext(executionContext)
	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

	//should update state after EvaluatePublicFunction
	err = example.UpdateStateVariables(states)
	assert.NoError(t, err)
}

func insertMap(t *testing.T, example *Contract, hashedMap *HashedMap, iKey int64, iVal int64) {
	prevLockingScript, err := example.GetLockingScript()

	assert.NoError(t, err)
	prevLockingScriptHex := hex.EncodeToString(*prevLockingScript)

	key := Int{big.NewInt(iKey)}
	val := Int{big.NewInt(iVal)}
	hashedMap.Set(key, val)

	sorteitem, err := example.GetStructTypeTemplate("SortedItem<int>")
	assert.NoError(t, err)

	err = sorteitem.UpdateValue("item", key)
	assert.NoError(t, err)

	idx, err := hashedMap.KeyIndex(key)
	assert.NoError(t, err)

	err = sorteitem.UpdateValue("idx", Int{big.NewInt(idx)})
	assert.NoError(t, err)

	entry, err := example.GetStructTypeTemplate("MapEntry")
	assert.NoError(t, err)
	entry.UpdateValue("key", sorteitem)
	entry.UpdateValue("val", val)

	states := map[string]ScryptType{
		"map": *hashedMap,
	}

	newLockingScript, err := example.getNewStateScript(states)

	assert.NoError(t, err)

	tx := bt.NewTx()
	err = tx.From(
		"a477ff6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458",
		0,
		prevLockingScriptHex,
		300000)
	assert.NoError(t, err)
	currOutput := bt.Output{
		Satoshis:      300000,
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"entry":    entry,
		"preimage": SigHashPreimage{preimage},
	}
	err = example.SetPublicFunctionParams("insert", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	example.SetExecutionContext(executionContext)
	success, err := example.EvaluatePublicFunction("insert")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

	//should update state after EvaluatePublicFunction
	err = example.UpdateStateVariables(states)
	assert.NoError(t, err)
}

func TestContractHashedMapAsState(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/LibAsState2.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	hashedMap := NewHashedMap()

	constructorParams := map[string]ScryptType{
		"map": hashedMap,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	// insert 111-111111
	insertMap(t, &example, &hashedMap, 111, 111111)

	// insert 222-22222
	insertMap(t, &example, &hashedMap, 222, 22222)

	// insert 333-33333
	insertMap(t, &example, &hashedMap, 333, 33333)

}

func TestContractHashedmap1(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/hashedmap1.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	stateMapTest, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	hashedmap := NewHashedMap()

	constructorParams := map[string]ScryptType{
		"map": hashedmap,
	}

	err = stateMapTest.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	prevLockingScript, err := stateMapTest.GetLockingScript()

	assert.NoError(t, err)
	prevLockingScriptHex := hex.EncodeToString(*prevLockingScript)

	states := map[string]ScryptType{
		"map": hashedmap,
	}

	newLockingScript, err := stateMapTest.getNewStateScript(states)

	assert.NoError(t, err)

	tx := bt.NewTx()
	err = tx.From(
		"a477ff6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458",
		0,
		prevLockingScriptHex,
		300000)
	assert.NoError(t, err)
	currOutput := bt.Output{
		Satoshis:      300000,
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"preimage": SigHashPreimage{preimage},
	}
	err = stateMapTest.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	stateMapTest.SetExecutionContext(executionContext)
	success, err := stateMapTest.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

	//should update state after EvaluatePublicFunction
	err = stateMapTest.UpdateStateVariables(states)
	assert.NoError(t, err)
}

func TestContractHashedset1(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/hashedset1.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	stateSetTest, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	hashedset := NewHashedSet()

	constructorParams := map[string]ScryptType{
		"set": hashedset,
	}

	err = stateSetTest.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	prevLockingScript, err := stateSetTest.GetLockingScript()

	assert.NoError(t, err)
	prevLockingScriptHex := hex.EncodeToString(*prevLockingScript)

	states := map[string]ScryptType{
		"set": hashedset,
	}

	newLockingScript, err := stateSetTest.getNewStateScript(states)

	assert.NoError(t, err)

	tx := bt.NewTx()
	err = tx.From(
		"a477ff6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458",
		0,
		prevLockingScriptHex,
		300000)
	assert.NoError(t, err)
	currOutput := bt.Output{
		Satoshis:      300000,
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"preimage": SigHashPreimage{preimage},
	}
	err = stateSetTest.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	stateSetTest.SetExecutionContext(executionContext)
	success, err := stateSetTest.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

	//should update state after EvaluatePublicFunction
	err = stateSetTest.UpdateStateVariables(states)
	assert.NoError(t, err)
}

func TestContractGenericSimple(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/genericsst_simple.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	a, err := example.GetStructTypeTemplate("ST<int>")
	assert.NoError(t, err)

	err = a.UpdateValue("x", Int{big.NewInt(1)})
	assert.NoError(t, err)
	err = a.UpdateValue("x", Bool{true})

	assert.Error(t, err)

	constructorParams := map[string]ScryptType{
		"a": a,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"a": a,
	}

	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractGenericCtor(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/genericsst_ctor.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	a, err := example.GetStructTypeTemplate("ST1<int>")
	assert.NoError(t, err)

	err = a.UpdateValue("x", Int{big.NewInt(1)})
	assert.NoError(t, err)

	b, err := example.GetStructTypeTemplate("ST1<int[3]>")
	assert.NoError(t, err)

	err = b.UpdateValue("x", Array{[]ScryptType{Int{big.NewInt(1)}, Int{big.NewInt(2)}, Int{big.NewInt(3)}}})
	assert.NoError(t, err)

	st0, err := example.GetStructTypeTemplate("ST0<int>")
	assert.NoError(t, err)

	err = st0.UpdateValue("x", Int{big.NewInt(1)})
	assert.NoError(t, err)

	err = st0.UpdateValue("y", Int{big.NewInt(2)})
	assert.NoError(t, err)

	c, err := example.GetStructTypeTemplate("ST1<ST0<int>>")
	assert.NoError(t, err)

	err = c.UpdateValue("x", st0)
	assert.NoError(t, err)

	st2_1, err := example.GetStructTypeTemplate("ST2")
	assert.NoError(t, err)

	err = st2_1.UpdateValue("x", Int{big.NewInt(1)})
	assert.NoError(t, err)

	st2_2, err := example.GetStructTypeTemplate("ST2")
	assert.NoError(t, err)

	err = st2_2.UpdateValue("x", Int{big.NewInt(2)})
	assert.NoError(t, err)

	d, err := example.GetStructTypeTemplate("ST1<ST2[2]>")
	assert.NoError(t, err)

	err = d.UpdateValue("x", Array{[]ScryptType{st2_1, st2_2}})
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{
		"a": a,
		"b": b,
		"c": c,
		"d": d,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"ap": a,
		"bp": b,
		"cp": c,
		"dp": d,
	}

	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractGenericsst_alias(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/genericsst_alias.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	a, err := example.GetStructTypeTemplate("ST3A")
	assert.NoError(t, err)

	b, err := example.GetStructTypeTemplate("ST0AA")
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{
		"a": a,
		"b": b,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"a": a,
		"b": b,
	}

	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractGenericsst(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/genericsst.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	a, err := example.GetStructTypeTemplate("ST1<int>")
	assert.NoError(t, err)

	err = a.UpdateValue("x", Int{big.NewInt(1)})
	assert.NoError(t, err)

	b, err := example.GetStructTypeTemplate("ST1<int[3]>")
	assert.NoError(t, err)

	err = b.UpdateValue("x", Array{[]ScryptType{Int{big.NewInt(1)}, Int{big.NewInt(2)}, Int{big.NewInt(3)}}})
	assert.NoError(t, err)

	st0, err := example.GetStructTypeTemplate("ST0<int>")
	assert.NoError(t, err)

	err = st0.UpdateValue("x", Int{big.NewInt(1)})
	assert.NoError(t, err)

	err = st0.UpdateValue("y", Int{big.NewInt(2)})
	assert.NoError(t, err)

	c, err := example.GetStructTypeTemplate("ST1<ST0<int>>")
	assert.NoError(t, err)

	err = c.UpdateValue("x", st0)
	assert.NoError(t, err)

	st2_1, err := example.GetStructTypeTemplate("ST2")
	assert.NoError(t, err)

	err = st2_1.UpdateValue("x", Int{big.NewInt(1)})
	assert.NoError(t, err)

	st2_2, err := example.GetStructTypeTemplate("ST2")
	assert.NoError(t, err)

	err = st2_2.UpdateValue("x", Int{big.NewInt(2)})
	assert.NoError(t, err)

	d, err := example.GetStructTypeTemplate("ST1<ST2[2]>")
	assert.NoError(t, err)

	err = d.UpdateValue("x", Array{[]ScryptType{st2_1, st2_2}})
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{
		"a": a,
		"b": b,
		"c": c,
		"d": d,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	ust2_1, err := example.GetStructTypeTemplate("ST2")
	assert.NoError(t, err)

	err = ust2_1.UpdateValue("x", Int{big.NewInt(1)})
	assert.NoError(t, err)

	ust2_2, err := example.GetStructTypeTemplate("ST2")
	assert.NoError(t, err)

	err = ust2_2.UpdateValue("x", Int{big.NewInt(2)})
	assert.NoError(t, err)

	ust2_3, err := example.GetStructTypeTemplate("ST2")
	assert.NoError(t, err)

	err = ust2_3.UpdateValue("x", Int{big.NewInt(3)})
	assert.NoError(t, err)

	ust0, err := example.GetStructTypeTemplate("ST0<ST2[3]>")
	assert.NoError(t, err)
	err = ust0.UpdateValue("x", Int{big.NewInt(11)})
	assert.NoError(t, err)
	err = ust0.UpdateValue("y", Array{[]ScryptType{ust2_1, ust2_2, ust2_3}})
	assert.NoError(t, err)

	ust1, err := example.GetStructTypeTemplate("ST1<ST0<ST2[3]>>")
	assert.NoError(t, err)

	err = ust1.UpdateValue("x", ust0)
	assert.NoError(t, err)

	ust1a := Array{[]ScryptType{ust1, ust1}}

	ust0a, err := example.GetStructTypeTemplate("ST0<ST1<ST0<ST2[3]>>[2]>")
	assert.NoError(t, err)

	err = ust0a.UpdateValue("x", Int{big.NewInt(111)})
	assert.NoError(t, err)

	err = ust0a.UpdateValue("y", ust1a)
	assert.NoError(t, err)

	ua, err := example.GetStructTypeTemplate("ST3<ST1<ST0<ST2[3]>>[2]>")
	assert.NoError(t, err)

	err = ua.UpdateValue("x", ust1a)
	assert.NoError(t, err)

	err = ua.UpdateValue("st0", ust0a)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"a": ua,
	}

	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractGenericsst1(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/genericsst1.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	l, err := example.GetLibraryTypeTemplate("L<ST1<ST0<ST2[2]>>>")
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{
		"l": l,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	st2, err := example.GetStructTypeTemplate("ST2")
	assert.NoError(t, err)

	st2.UpdateValue("x", Int{big.NewInt(111)})

	st0, err := example.GetStructTypeTemplate("ST0<ST2[2]>")
	assert.NoError(t, err)

	err = st0.UpdateValue("y", Array{[]ScryptType{st2, st2}})
	assert.NoError(t, err)
	v, err := example.GetStructTypeTemplate("ST1<ST0<ST2[2]>>")
	assert.NoError(t, err)

	err = v.UpdateValue("x", st0)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"v": v,
	}

	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractGenericsst2(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/genericsst2.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	a, err := example.GetStructTypeTemplate("ST0<int[3], bool[1]>")
	assert.NoError(t, err)

	l, err := example.GetLibraryTypeTemplate("L<ST0<int[3], bool[1]>>")
	assert.NoError(t, err)

	l.UpdateValue("x", a)

	constructorParams := map[string]ScryptType{
		"a": a,
		"l": l,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	aa, err := example.GetStructTypeTemplate("ST0<int, bool>")
	assert.NoError(t, err)

	err = aa.UpdateValue("x", Bool{true})
	assert.NoError(t, err)

	err = aa.UpdateValue("y", Int{big.NewInt(1)})
	assert.NoError(t, err)

	aaa, err := example.GetStructTypeTemplate("ST0<int[3], bool[1]>")
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"aa":  aa,
		"aaa": aaa,
	}

	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractGenericsst4(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/genericsst4.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	l, err := example.GetLibraryTypeTemplate("L")
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{
		"l": l,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	a, err := example.GetStructTypeTemplate("ST0<int[3], bool[1]>")
	assert.NoError(t, err)

	b, err := example.GetStructTypeTemplate("ST0<bool, bytes>")
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"a": a,
		"b": b,
	}

	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractGenericsst6(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/genericsst6.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	st0, err := example.GetStructTypeTemplate("ST0<int[2], int>")
	assert.NoError(t, err)

	st0.UpdateValue("x", Int{big.NewInt(1)})
	st0.UpdateValue("y", Array{[]ScryptType{Int{big.NewInt(2)}, Int{big.NewInt(3)}}})

	st1, err := example.GetStructTypeTemplate("ST1<int[2], int>")
	assert.NoError(t, err)

	st1.UpdateValue("x", st0)
	st1.UpdateValue("y", Array{[]ScryptType{Int{big.NewInt(4)}, Int{big.NewInt(5)}}})

	st2, err := example.GetStructTypeTemplate("ST2<int>")
	assert.NoError(t, err)

	st2.UpdateValue("x", st1)
	st2.UpdateValue("y", Int{big.NewInt(100)})

	l, err := example.GetLibraryTypeTemplate("L")
	assert.NoError(t, err)

	l.UpdateValue("st2", st2)

	constructorParams := map[string]ScryptType{
		"l": l,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"st2": st2,
	}

	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractGenericsst7(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/genericsst7.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{
		"hm": NewHashedMap(),
		"hs": NewHashedSet(),
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	tx := bt.NewTx()

	lockingScript, err := example.GetLockingScript()
	assert.NoError(t, err)
	lockingScriptHex := hex.EncodeToString(*lockingScript)
	err = tx.From(
		"a3865bd4351665c7531a4311f250c1eac5d6775da5ced72b4b83cfee625b6947", // Random TXID
		0,
		lockingScriptHex,
		5000)
	assert.NoError(t, err)

	st0, err := example.GetStructTypeTemplate("ST0<int>")
	assert.NoError(t, err)

	st0.UpdateValue("x", Int{big.NewInt(1)})
	st0.UpdateValue("y", Int{big.NewInt(12)})

	hashedmap := NewHashedMap()
	hashedset := NewHashedSet()

	hashedmap.Set(Int{big.NewInt(11)}, st0)

	hashedset.Add(st0)

	states := map[string]ScryptType{
		"hm": hashedmap,
		"hs": hashedset,
	}

	newLockingScript, err := example.getNewStateScript(states)
	assert.NoError(t, err)

	tx.AddOutput(&bt.Output{
		Satoshis:      5000,
		LockingScript: newLockingScript,
	})

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	key, err := example.GetStructTypeTemplate("SortedItem<int>")
	assert.NoError(t, err)

	err = key.UpdateValue("item", Int{big.NewInt(11)})
	assert.NoError(t, err)

	keyIndex, err := hashedmap.KeyIndex(Int{big.NewInt(11)})
	assert.NoError(t, err)

	err = key.UpdateValue("idx", Int{big.NewInt(keyIndex)})
	assert.NoError(t, err)

	e, err := example.GetStructTypeTemplate("SortedItem<ST0<int>>")
	assert.NoError(t, err)

	err = e.UpdateValue("item", st0)
	assert.NoError(t, err)

	keyIndexSet, err := hashedset.KeyIndex(st0)
	assert.NoError(t, err)

	err = e.UpdateValue("idx", Int{big.NewInt(keyIndexSet)})
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"key":        key,
		"val":        st0,
		"e":          e,
		"txPreimage": SigHashPreimage{preimage},
	}

	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	example.SetExecutionContext(executionContext)

	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractGenericsst8(t *testing.T) {

	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/genericsst8.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	example, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	st0, err := example.GetStructTypeTemplate("ST0<int>")
	assert.NoError(t, err)

	constructorParams := map[string]ScryptType{
		"st": st0,
	}

	err = example.SetConstructorParams(constructorParams)
	assert.NoError(t, err)

	tx := bt.NewTx()

	lockingScript, err := example.GetLockingScript()
	assert.NoError(t, err)
	lockingScriptHex := hex.EncodeToString(*lockingScript)
	err = tx.From(
		"a3865bd4351665c7531a4311f250c1eac5d6775da5ced72b4b83cfee625b6947", // Random TXID
		0,
		lockingScriptHex,
		5000)
	assert.NoError(t, err)

	st0_, err := example.GetStructTypeTemplate("ST0<int>")

	assert.NoError(t, err)

	st0_.UpdateValue("x", Int{big.NewInt(1)})
	st0_.UpdateValue("y", Int{big.NewInt(1)})

	states := map[string]ScryptType{
		"st": st0_,
	}

	newLockingScript, err := example.getNewStateScript(states)
	assert.NoError(t, err)

	tx.AddOutput(&bt.Output{
		Satoshis:      5000,
		LockingScript: newLockingScript,
	})

	preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"txPreimage": SigHashPreimage{preimage},
	}

	err = example.SetPublicFunctionParams("unlock", unlockParams)
	assert.NoError(t, err)

	executionContext := ExecutionContext{
		Tx:       tx,
		InputIdx: 0,
		Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
	}

	example.SetExecutionContext(executionContext)

	success, err := example.EvaluatePublicFunction("unlock")
	assert.NoError(t, err)
	assert.Equal(t, true, success)
}

func TestContractDecrypt(t *testing.T) {
	compilerResult, err := compilerWrapper.CompileContractFile("./test/res/decrypt.scrypt")
	assert.NoError(t, err)

	desc, err := compilerResult.ToDescWSourceMap()
	assert.NoError(t, err)

	decrypt, err := NewContractFromDesc(desc)
	assert.NoError(t, err)

	point, err := decrypt.GetStructTypeTemplate("Point")
	assert.NoError(t, err)

	point.UpdateValue("x", NewIntFromStr("112480853479035711358537547598792536024104305348634273328347848512657823854047", 10))
	point.UpdateValue("y", NewIntFromStr("7608050272491180713670563462900697273117387941835197652305163436291393634715", 10))

	privKey, err := PrivKeyFromHex("c06b852b1f15414607be60e304ef6d0b74742929063971f2d0b1ad72d7a2d5f7")
	assert.NoError(t, err)

	unlockParams := map[string]ScryptType{
		"privKey": privKey,
		"K":       point,
	}
	err = decrypt.SetPublicFunctionParams("decrypt", unlockParams)
	assert.NoError(t, err)

	success, err := decrypt.EvaluatePublicFunction("decrypt")
	assert.NoError(t, err)
	assert.Equal(t, true, success)

}
