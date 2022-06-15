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

// TODO:
//func TestContractGenericsTest(t *testing.T) {
//
//	source := `
//        contract GenericsTest {
//            public function add2Set(SortedItem<int> val) {
//                HashedSet<int> set = new HashedSet(b'');
//                require(set.add(val));
//                require(set.has(val));
//                require(true);
//            }
//            public function add2Map(SortedItem<int> key, int val) {
//                HashedMap<int, int> map = new HashedMap(b'');
//                require(map.set(key, val));
//                require(map.canGet(key, val));
//                require(true);
//            }
//        }
//    `
//
//	compilerResult, err := compilerWrapper.CompileContractString(source)
//	assert.NoError(t, err)
//
//	desc, err := compilerResult.ToDescWSourceMap()
//	assert.NoError(t, err)
//
//	hashedMapSetTest, err := NewContractFromDesc(desc)
//	assert.NoError(t, err)
//
//    fmt.Println(hashedMapSetTest)
//}
