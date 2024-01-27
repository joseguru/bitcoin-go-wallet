package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"github.com/brianium/mnemonic"
	"github.com/btcsuite/btcd/btcutil/base58"
	// "github.com/btcsuite/btcd/btcec/v2"
	// "github.com/btcsuite/btcd/btcutil"
	// "github.com/btcsuite/btcd/chaincfg"
)	

type HDWallet struct {
	Vbytes      []byte //4 bytes
	Depth       uint16 //1 byte
	Fingerprint []byte //4 bytes
	I           []byte //4 bytes
	Chaincode   []byte //32 bytes
	Key         []byte //33 bytes
}
var (
	//MainNet
	Public  []byte
	Private []byte
	//TestNet
	TestPublic  []byte
	TestPrivate []byte
)

func init() {
	Public, _ = hex.DecodeString("0488B21E")
	Private, _ = hex.DecodeString("0488ADE4")
	TestPublic, _ = hex.DecodeString("043587CF")
	TestPrivate, _ = hex.DecodeString("04358394")
}
func main(){
	
	seed := createHash();
	
	mnemonic,_ :=mnemonic.New([]byte(seed),mnemonic.English)

	masterprv:= MasterKey([]byte(mnemonic.Sentence()))
	
	masterpub := masterprv.Pub()

	// Get your address
	address := masterpub.Address()

	//fmt.Println("Wallet")
	fmt.Printf("Address: %v \n", address)
	// fmt.Printf("Private Key: %v \n", masterprv)
	// fmt.Printf("Public Key: %v \n", masterpub)
	// fmt.Printf("Seed: %v \n", mnemonic.Sentence())

}
func (w *HDWallet) Address() string {
	x, y := expand(w.Key)
	four, _ := hex.DecodeString("04")
	padded_key := append(four, append(x.Bytes(), y.Bytes()...)...)
	var prefix []byte
	if bytes.Compare(w.Vbytes, TestPublic) == 0 || bytes.Compare(w.Vbytes, TestPrivate) == 0 {
		prefix, _ = hex.DecodeString("6F")
	} else {
		prefix, _ = hex.DecodeString("00")
	}
	addr_1 := append(prefix, hash160(padded_key)...)
	chksum := dblSha256(addr_1)
	return base58.Encode(append(addr_1, chksum[:4]...))
}
func (w *HDWallet) Pub() *HDWallet {
	if bytes.Compare(w.Vbytes, TestPublic) == 0 {
		return &HDWallet{w.Vbytes, w.Depth, w.Fingerprint, w.I, w.Chaincode, w.Key}
	} else {
		return &HDWallet{TestPublic, w.Depth, w.Fingerprint, w.I, w.Chaincode, privToPub(w.Key)}
	}
}
func createHash() string{
	key :=make([]byte,8)
	_,err := rand.Read(key)
	if err != nil {
		// handle error here
		fmt.Println(err)
	}
	str := hex.EncodeToString(key)

	return str

}
func MasterKey(seed []byte) *HDWallet {
	key := []byte("Bitcoin seed")
	mac := hmac.New(sha512.New, key)
	mac.Write(seed)
	I := mac.Sum(nil)
	secret := I[:len(I)/2]
	chain_code := I[len(I)/2:]
	depth := 0
	i := make([]byte, 4)
	fingerprint := make([]byte, 4)
	zero := make([]byte, 1)
	return &HDWallet{TestPrivate, uint16(depth), fingerprint, i, chain_code, append(zero, secret...)}
}

