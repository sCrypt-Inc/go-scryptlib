package scryptlib

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/libsv/go-bk/crypto"
	"github.com/libsv/go-bk/wif"
	"github.com/libsv/go-bt/v2"
	"github.com/libsv/go-bt/v2/bscript/interpreter/scriptflag"
	"github.com/libsv/go-bt/v2/sighash"
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

	counter.SetDataPart("00")

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

	newLockingScript, err := counter.GetNewLockingScript("01")

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

func TestContractStateCounter(t *testing.T) {
	/*
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

		unlockParams := map[string]ScryptType{
			"txPreimage": SigHashPreimage{preimage},
			"amount":     Int{big.NewInt(4800)},
		}
		err = contractStateCounter.SetPublicFunctionParams("unlock", unlockParams)
		assert.NoError(t, err)

		executionContext := ExecutionContext{
			Tx:       tx,
			InputIdx: 0,
			Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
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

		unlockParams = map[string]ScryptType{
			"txPreimage": SigHashPreimage{preimage},
			"amount":     Int{big.NewInt(4800)},
		}
		err = contractStateCounter.SetPublicFunctionParams("unlock", unlockParams)
		assert.NoError(t, err)

		executionContext = ExecutionContext{
			Tx:       tx,
			InputIdx: 0,
			Flags:    scriptflag.EnableSighashForkID | scriptflag.UTXOAfterGenesis,
		}

		contractStateCounter.SetExecutionContext(executionContext)
		success, err = contractStateCounter.EvaluatePublicFunction("unlock")
		assert.Error(t, err)
		assert.Equal(t, false, success)

		// Wrong amount:
		err = contractStateCounter.UpdateStateVariable("counter", Int{big.NewInt(1)})
		assert.NoError(t, err)
		unlockParams = map[string]ScryptType{
			"txPreimage": SigHashPreimage{preimage},
			"amount":     Int{big.NewInt(4799)},
		}
		err = contractStateCounter.SetPublicFunctionParams("unlock", unlockParams)
		success, err = contractStateCounter.EvaluatePublicFunction("unlock")
		assert.Error(t, err)
		assert.Equal(t, false, success)
	*/
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

func TestContractToken(t *testing.T) {
	/*
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

		new_account0 := token.GetStructTypeTemplate("Account")
		new_account0.UpdateValue("pubKey", PubKey{priv0.PubKey()})
		new_account0.UpdateValue("balance", Int{big.NewInt(60)})
		new_account1 := token.GetStructTypeTemplate("Account")
		new_account1.UpdateValue("pubKey", PubKey{priv1.PubKey()})
		new_account1.UpdateValue("balance", Int{big.NewInt(40)})
		new_accounts := Array{[]ScryptType{new_account0, new_account1}}

		constructorParams := map[string]ScryptType{
			"accounts": new_accounts,
		}
		err = token.SetConstructorParams(constructorParams)
		assert.NoError(t, err)

		newLockingScript, err := token.GetLockingScript()
		assert.NoError(t, err)

		account0 := token.GetStructTypeTemplate("Account")
		account0.UpdateValue("pubKey", PubKey{priv0.PubKey()})
		account0.UpdateValue("balance", Int{big.NewInt(100)})
		account1 := token.GetStructTypeTemplate("Account")
		account1.UpdateValue("pubKey", PubKey{priv1.PubKey()})
		account1.UpdateValue("balance", Int{big.NewInt(0)})
		accounts := Array{[]ScryptType{account0, account1}}

		constructorParams = map[string]ScryptType{
			"accounts": accounts,
		}
		err = token.SetConstructorParams(constructorParams)
		assert.NoError(t, err)

		prevLockingScript, err := token.GetLockingScript()
		assert.NoError(t, err)
		prevLockingScriptHex := hex.EncodeToString(*prevLockingScript)

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
	*/
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
		otherThing := nestedStructs.GetStructTypeTemplate("OtherThing")
		otherThing.UpdateValue("someBytes", Bytes{make([]byte, 3)})
		numVals := make([]ScryptType, 3)
		for j := 0; j < 3; j++ {
			numVals[j] = Int{big.NewInt(0)}
		}
		otherThing.UpdateValue("numbers", Array{numVals})
		otherThingsVals[i] = otherThing
	}

	thing := nestedStructs.GetStructTypeTemplate("Thing")
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

	l := libAsPropertyTest.GetLibraryTypeTemplate("L")
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

	l := libAsPropertyTest.GetLibraryTypeTemplate("L")
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

	l := library1.GetLibraryTypeTemplate("L")

	l.UpdateValue("a", Int{big.NewInt(1)})
	l.UpdateValue("b", Int{big.NewInt(2)})

	l1 := library1.GetLibraryTypeTemplate("L1")
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

	st := library2.GetStructTypeTemplate("ST")

	st.UpdateValue("a", Array{[]ScryptType{Int{big.NewInt(4)}, Int{big.NewInt(5)}}})
	st.UpdateValue("b", Bool{false})
	st.UpdateValue("c", Bytes{[]byte{0x01, 0xef, 0x02}})
	l := library2.GetLibraryTypeTemplate("L")

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

	l := library3.GetLibraryTypeTemplate("L")

	l.UpdateValue("a", Int{big.NewInt(1)})
	l.UpdateValue("b", Int{big.NewInt(2)})

	l1 := library3.GetLibraryTypeTemplate("L1")

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

	l1 := library3.GetLibraryTypeTemplate("L1")

	l1.UpdateValue("a", Int{big.NewInt(1)})
	l1.UpdateValue("b", Int{big.NewInt(2)})

	st := library3.GetStructTypeTemplate("ST")

	st.UpdateValue("x", Int{big.NewInt(2)})

	l2 := library3.GetLibraryTypeTemplate("L2")

	l2.UpdateValue("x", Array{[]ScryptType{st}})

	l3 := library3.GetLibraryTypeTemplate("L3")

	l3.UpdateValue("l1", l1)
	l3.UpdateValue("l2", l2)

	l4 := library3.GetLibraryTypeTemplate("L4")

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

func runPut(t *testing.T, hashedmap Contract, hm HashedMap, pkh Ripemd160, balance int64) {

	data, _ := hm.Hex()

	dataPart, _ := serializeState(data, STATE_LEN_3BYTES)

	hashedmap.SetDataPart(dataPart)

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

	newdata, _ := hm.Hex()

	newDataPart, _ := serializeState(newdata, STATE_LEN_3BYTES)

	newLockingScript, err := hashedmap.GetNewLockingScript(newDataPart)
	assert.NoError(t, err)
	currOutput := bt.Output{
		Satoshis:      5000,
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	key := hashedmap.GetStructTypeTemplate("Key")

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
	hashedmap.SetDataPart(newDataPart)
}

func runDelete(t *testing.T, hashedmap Contract, hm HashedMap, pkh Ripemd160) {

	data, _ := hm.Hex()

	dataPart, _ := serializeState(data, STATE_LEN_3BYTES)

	hashedmap.SetDataPart(dataPart)

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

	newdata, _ := hm.Hex()

	newDataPart, _ := serializeState(newdata, STATE_LEN_3BYTES)

	newLockingScript, err := hashedmap.GetNewLockingScript(newDataPart)
	assert.NoError(t, err)
	currOutput := bt.Output{
		Satoshis:      5000,
		LockingScript: newLockingScript,
	}
	tx.AddOutput(&currOutput)

	key := hashedmap.GetStructTypeTemplate("Key")

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
	hashedmap.SetDataPart(newDataPart)
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
	runPut(t, hashedmap, hm, pkh, int64(balance))

	//update balance
	balance = 11111111
	runPut(t, hashedmap, hm, pkh, int64(balance))

	// PUT one more key-value pair

	pkh1 := NewPKH("cQcjHS827WgD9yu7JDEPzxcZnYMBde7yjQoiiMBDTC6hG55m4ME3")
	runPut(t, hashedmap, hm, pkh1, 21000)

	// PUT one more key-value pair
	pkh2 := NewPKH("cQrRVKafjo7Hy4HFD8NJWUUW4h9M9deQhBu6V6YTQpUcRQvfswHJ")
	runPut(t, hashedmap, hm, pkh2, 100000)
	runPut(t, hashedmap, hm, pkh2, 0)

	//	PUT one more key-value pair
	pkh3 := NewPKH("cV3hHnEZekLakJc8aLohu7yq5PTjVT41mx4r6FzGRCi38sZ8c7kY")
	runPut(t, hashedmap, hm, pkh3, 100)

	runDelete(t, hashedmap, hm, pkh2)

}
