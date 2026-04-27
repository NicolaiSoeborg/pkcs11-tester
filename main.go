package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"golang.org/x/term"
)

const (
	SLOT = 0
	//hsmPath = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
	//hsmPath = "/usr/lib64/opensc-pkcs11.so"
	//hsmPath = "/opt/BouncyHsm/artifacts/.tmp/native/Linux-x64/BouncyHsm.Pkcs11Lib.so"

	NoiseKeySize = 32
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <path to PKCS#11 library>\n", os.Args[0])
		os.Exit(1)
	}
	hsmPath := os.Args[1]

	module, err := p11.OpenModule(hsmPath)
	if err != nil {
		panic(fmt.Errorf("[ERR] failed to load module library: %s", hsmPath))
	}
	fmt.Printf("[OK] Module '%s' loaded correctly\n", hsmPath)
	defer module.Destroy()

	slots, err := module.Slots()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Found %d slots\n", len(slots))

	if uint(len(slots)) <= SLOT {
		panic(fmt.Errorf("[ERR] Requested slot (%d) but only %d available", SLOT, len(slots)))
	}

	// try to open a session on the slot
	session, err := slots[SLOT].OpenSession()
	if err != nil {
		panic(fmt.Errorf("[ERR] failed to open session on slot %d", SLOT))
	}
	fmt.Printf("[OK] OpenSession on slot %d worked\n", SLOT)
	defer session.Close()

	// try to login to the slot
	fmt.Printf("Enter Pin for slot %d:\n", SLOT)
	userPin, _ := term.ReadPassword(0) // no echo
	pin := strings.TrimSpace(string(userPin))
	err = session.Login(pin)
	if err != nil {
		panic(fmt.Errorf("[ERR] Login unsuccessful: %w", err))
	}
	fmt.Printf("[OK] Login successful\n")
	defer session.Logout()

	var X25519_OID = []byte{0x06, 0x03, 0x2b, 0x65, 0x6e} // "06032B656E"  // 1.3.101.110 ("id-X25519")

	privateAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, X25519_OID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		//pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC_MONTGOMERY),
		pkcs11.NewAttribute(pkcs11.CKA_ALLOWED_MECHANISMS, pkcs11.CKM_ECDH1_DERIVE),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true), // private key should be allowed to derive a shared secret
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),  // look only for "token objects" (persisted on HSM)
	}

	// FindObject expects a single key with above attrs, otherwise it returns err
	privateKey, err := session.FindObject(privateAttrs)
	if err != nil {
		panic(fmt.Errorf("[ERR] Could not find private key with attrs: %w", err))
	}
	fmt.Printf("[OK] Found privateKey ref: %x\n", privateKey)

	ckaId, err := privateKey.Attribute(pkcs11.CKA_ID)
	if err != nil {
		panic(fmt.Errorf("[ERR] Could not find CKA_ID of private key: %w", err))
	}
	fmt.Printf("[OK] Found CKA_ID of privateKey: %s\n", ckaId)

	publicAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, X25519_OID), // public key be specified on the id-X25519 curve
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		//pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), // look only for "token objects" (persisted on HSM)
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaId),
	}

	publicKey, err := session.FindObject(publicAttrs)
	if err != nil {
		panic(fmt.Errorf("[ERR] Could not find public key: %w", err))
	}

	fmt.Printf("[OK] Found publicKey ref: %x\n", publicKey)

	// From my understanding, for X25519 the public key is not stored
	// in `CKA_VALUE` but instead in attribute `CKA_EC_POINT`.
	// "DER-encoding of the public key value in little endian order as defined in RFC 7748"
	// - https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html
	pubKeyVal, err := publicKey.Attribute(pkcs11.CKA_EC_POINT)
	if err != nil {
		panic(err)
	}
	if len(pubKeyVal) != NoiseKeySize {
		// On a Nitrokey Start, this gets the full EC_POINT value of 34 bytes instead of 32,
		// If prefix is "04 (OCTET STRING) 20 (of length 0x20)" then discard the prefix
		// TODO: Probably this is correct and the returned value should always be 34 bytes!?
		if len(pubKeyVal) == NoiseKeySize+2 && pubKeyVal[0] == 0x04 && pubKeyVal[1] == 0x20 {
			pubKeyVal = pubKeyVal[2:]
		} else {
			panic(fmt.Errorf("[ERR] Key of wrong size returned (%d): %x", len(pubKeyVal), pubKeyVal))
		}
	}

	fmt.Printf("[OK] Public Key (base64): %s\n", base64.StdEncoding.EncodeToString(pubKeyVal))

	// derive a shared secret using (publicKey, privateKey) (so only shared between oneself)
	peerPubKey := pubKeyVal

	// before we call derive, we need to have an array of attributes which specify the type of
	// key to be returned, in our case, it's the shared secret key, produced via deriving
	// This template pulled from OpenSC pkcs11-tool.c line 4038
	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET), // output (shared secret) is a raw byte string with no structure ("generic secret")
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),                        // we want to derive a "session object" (temporary for this session only)
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),                   // shared secret can be exported to software
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),                    // shared secret can be exported raw
	}

	// setup the parameters which include the peer's public key
	ecdhParams := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPubKey)

	var deriveMech *pkcs11.Mechanism = pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, ecdhParams)

	// derive the secret key from the public key as input and the private key on the device
	resultKey, err := p11.PrivateKey(privateKey).Derive(*deriveMech, attrTemplate)
	if err != nil {
		panic(err)
	}
	if len(resultKey) != NoiseKeySize {
		panic(fmt.Errorf("[ERR] Wrong size derived (%d)", len(resultKey)))
	}

	fmt.Printf("[OK] Derived key worked\n")

}
