package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
)

var StartAmount = 75000 /// Assumed salary
var ContractKey = "contract"
var SenderIP = "0.0.0.0"
var SenderPort = "0"

type SimpleAsset struct {
}

type Party struct {
	PubKey    string
	IPAddress string
	Port      string
}

type APDL struct {
	Status         string
	SoftwareOwner  Party
	SoftwareUser   Party
	ContractExpiry time.Time
	DepositAmount  int
}

// Init called with the intention to create a new NDA contract
func (t *SimpleAsset) Init(stub shim.ChaincodeStubInterface) peer.Response {
	// Init contract state
	apdl := APDL{"init", Party{}, Party{}, time.Now(), 0}
	b, err := json.Marshal(apdl)
	err = stub.PutState(ContractKey, b)
	if err != nil {
		return shim.Error("[-] Failed to process download request transaction. Error!")
	}
	return shim.Success([]byte("[+] Init completed\n"))
}

// Invoke is called per transaction on the chaincode.
func (t *SimpleAsset) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	// Extract the function and args from the transaction proposal
	fn, args := stub.GetFunctionAndParameters()

	var result string
	var err error
	result = fn
	if fn == "download_request" {
		args := stub.GetStringArgs()
		// args = [{function}, sender_pk, recipient_pk, amount, deposit_time, recipient_ip, recipient_port]
		if len(args) != 7 {
			return shim.Error("Incorrect number of arguments. Got " + strconv.Itoa(len(args)) + ": " + strings.Join(args, ",") +
				"Expecting [sender_pk, recipient_pk, deposit_amount, deposit_time, recipient_ip, recipient_port]")
		}

		amount, err := strconv.Atoi(args[3])
		if err != nil || amount < 0 {
			return shim.Error("Invalid amount passed")
		}
		dt, err := time.Parse("01/02/2006", args[4])
		if err != nil {
			return shim.Error("Unable to parse: " + args[4] + " Error: " + err.Error())
		} else if !dt.After(time.Now()) {
			errMessage := "Invalid (past) time passed: " +
				dt.Format("01/02/2006") + ". Time Now: " +
				time.Now().Format("01/02/2006")
			return shim.Error(errMessage)
		}
		senderPublicKey := args[1]
		recipientPublicKey := args[2]
		ds := Party{PubKey: senderPublicKey, IPAddress: SenderIP, Port: SenderPort}
		dr := Party{PubKey: recipientPublicKey, IPAddress: args[5], Port: args[6]}
		apdl := APDL{Status: "download_requested", SoftwareOwner: ds, SoftwareUser: dr, ContractExpiry: dt, DepositAmount: amount}
		initialAmount := []byte(strconv.Itoa(StartAmount - amount))
		err = stub.PutState(senderPublicKey, initialAmount)
		err = stub.PutState(recipientPublicKey, initialAmount)
		b, err := json.Marshal(apdl)
		err = stub.PutState(ContractKey, b)
		if err != nil {
			return shim.Error("[-] Failed to process download request transaction. Error!")
		}
	} else if fn == "penalty" {
		// args = [{function}, message, hubSig, userSig]
		// Xsig (where X is a party) = "rStr,sStr"
		if len(args) != 4 {
			return shim.Error("need to pass recipient sig")
		}
		contract, err := stub.GetState(ContractKey)
		if err != nil {
			return shim.Error("[-] Failed to get contract")
		}
		var apdl APDL
		json.Unmarshal(contract, &apdl)
		// check if status is active to prevent double penalty.
		if apdl.Status == "init" || apdl.Status == "penalized" {
			return shim.Error("[-] Invalid status for penalty. Current status: " + apdl.Status)
		}
		publicKeys := []string{apdl.SoftwareOwner.PubKey, apdl.SoftwareUser.PubKey}
		cmp1 := apdl.SoftwareOwner.PubKey + " vs. " + args[2]
		cmp2 := apdl.SoftwareUser.PubKey + " vs. " + args[3]
		signatures := []string{args[2], args[3]}
		if verifySig(args[1], publicKeys, signatures) != true {
			return shim.Error("[-] Signature verification failed. Penalty not applied. comparisons: " + cmp1 + "---" + cmp2)
		}
		value, err := stub.GetState(apdl.SoftwareUser.PubKey)
		balance, _ := strconv.Atoi(string(value))
		balance = balance - apdl.DepositAmount
		endBalance := []byte(strconv.Itoa(balance))
		stub.PutState(apdl.SoftwareUser.PubKey, endBalance)
		apdl.Status = "penalized"
		b, err := json.Marshal(apdl)
		stub.PutState(ContractKey, b)
		result = "[+] Penalty applied\n"

	} else if fn == "refund" {
		// args = [{function}]
		contract, err := stub.GetState(ContractKey)
		if err != nil {
			return shim.Error(err.Error())
		}
		var apdl APDL
		json.Unmarshal(contract, &apdl)
		if apdl.Status != "download_request" {
			return shim.Error("[-] Invalid status for refund. Current status: " + apdl.Status)
		}
		tnow := time.Now()
		if tnow.After(apdl.ContractExpiry) {
			apdl.Status = "expired"
			b, _ := json.Marshal(apdl)
			stub.PutState(ContractKey, b)
			value, _ := stub.GetState(apdl.SoftwareUser.PubKey)
			balance, _ := strconv.Atoi(string(value))
			balance = balance + apdl.DepositAmount
			endBalance := []byte(strconv.Itoa(balance))
			stub.PutState(apdl.SoftwareUser.PubKey, endBalance)
			result = "[+] APDL contract expired."
		} else {
			return shim.Error("[-] APDL contract not yet expired")
		}
	} else if fn == "get_status" {
		// args = [{function}]
		contract, err := stub.GetState(ContractKey)
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(contract)
	}
	if err != nil {
		return shim.Error(err.Error())
	}
	// Return the result as success payload
	return shim.Success([]byte(result))
}

// message, apdl.SoftwareOwner.PubKey, apdl.SoftwareUser.PubKey, recipientSig, senderSig
// Xsig (where X is a party) = "rStr,sStr"
func verifySig(message string, publicKeys []string, signatures []string) bool {
	verified := false
	if len(publicKeys) != len(signatures) {
		return false
	}

	for i := 0; i < len(publicKeys); i++ {
		publicKeyBytes, err := base64.URLEncoding.DecodeString(publicKeys[i])
		publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
		if err != nil {
			return false
		}
		sig := strings.Split(signatures[i], ",")
		if len(sig) < 2 {
			return false
		}
		r := new(big.Int)
		r.SetString(sig[0], 0)
		s := new(big.Int)
		s.SetString(sig[1], 0)
		switch publicKey := publicKey.(type) {
		case *ecdsa.PublicKey:
			verified = ecdsa.Verify(publicKey, []byte(message), r, s)
		default:
			return false
		}
	}
	return verified
}

// main function starts up the chaincode in the container during instantiate
func main() {
	if err := shim.Start(new(SimpleAsset)); err != nil {
		fmt.Printf("Error starting SimpleAsset chaincode: %s", err)
	}
}
