package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"golang.org/x/term"
)

const (
	SLOT = 0
	HsmPath = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"

	CURVE25519_OID_RAW = "06032B656E"  // 1.3.101.110 ("id-X25519")
	NoiseKeySize = 32
)

func main() {
	module, err := p11.OpenModule(HsmPath)
	if err != nil {
		panic(fmt.Errorf("failed to load module library: %s", HsmPath))
	}
	fmt.Printf("Module '%s' loaded correctly\n", HsmPath)

	slots, err := module.Slots()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Found %d slots\n", len(slots))

	if uint(len(slots)) <= SLOT {
		panic(fmt.Errorf("Requested slot (%d) but only %d available", SLOT, len(slots)))
	}

	// try to open a session on the slot
	session, err := slots[SLOT].OpenWriteSession()
	if err != nil {
		panic(fmt.Errorf("failed to open session on slot %d", SLOT))
	}
	fmt.Printf("OpenWriteSession on slot %d worked\n", SLOT)

	// try to login to the slot
	fmt.Printf("Enter Pin for slot %d:\n", SLOT)
	userPin, _ := term.ReadPassword(0) // no echo
	pin := strings.TrimSpace(string(userPin))
	err = session.Login(pin)
	if err != nil {
		panic(fmt.Errorf("Login unsuccessful: %w", err))
	}
	fmt.Printf("Login successful\n")

	rawOID, _ := hex.DecodeString(CURVE25519_OID_RAW)

	privateAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, rawOID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	// FindObject expects a single key with above attrs, otherwise it returns err
	privateKey, err := session.FindObject(privateAttrs)
	if err != nil {
		panic(fmt.Errorf("Could not find private key with attrs: %w", err))
	}
	fmt.Printf("Found privateKey ref: %x\n", privateKey)

	ckaId, err := privateKey.Attribute(pkcs11.CKA_ID);
	if err != nil {
		panic(fmt.Errorf("Could not find CKA_ID of private key: %w", err))
	}
	fmt.Printf("Found CKA_ID of privateKey: %s\n", ckaId)

	publicAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, rawOID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaId),
	}

	publicKey, err := session.FindObject(publicAttrs)
	if err != nil {
		panic(fmt.Errorf("Could not find public key: %w", err))
	}

	fmt.Printf("Found publicKey ref: %x\n", publicKey)

	// From my understanding, for X25519 the public key is not stored
	// in `CKA_VALUE` but instead in attribute `CKA_EC_POINT`.
	// "DER-encoding of the public key value in little endian order as defined in RFC 7748"
	// - https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html
	pubKeyVal, err := publicKey.Attribute(pkcs11.CKA_EC_POINT);
	if err != nil {
		panic(err)
	}
	if len(pubKeyVal) != NoiseKeySize {
		// On a Nitrokey Start, this gets the full EC_POINT value of 34 bytes instead of 32,
		// If prefix is "04 (OCTET STRING) 20 (of length 0x20)" then discard the prefix
		// TODO: Probably this is correct and the returned value should always be 34 bytes!?
		if len(pubKeyVal) == NoiseKeySize + 2 && pubKeyVal[0] == 0x04 && pubKeyVal[1] == 0x20 {
			pubKeyVal = pubKeyVal[2:]
		} else {
			panic(fmt.Errorf("Key of wrong size returned (%d): %x", len(pubKeyVal), pubKeyVal))
		}
	}

	fmt.Printf("Public Key Val (EC_POINT): %x\n", pubKeyVal)
	fmt.Printf("Public Key Val (EC_POINT), b64: %s\n", base64.StdEncoding.EncodeToString(pubKeyVal))

    // derive a shared secret using (publicKey, privateKey) (so only shared between oneself)
	peerPubKey := pubKeyVal

	var mech_mech uint = pkcs11.CKM_ECDH1_DERIVE

	// before we call derive, we need to have an array of attributes which specify the type of
	// key to be returned, in our case, it's the shared secret key, produced via deriving
	// This template pulled from OpenSC pkcs11-tool.c line 4038
	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	}

	// setup the parameters which include the peer's public key
	ecdhParams := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPubKey)

	var mech *pkcs11.Mechanism = pkcs11.NewMechanism(mech_mech, ecdhParams)

	// derive the secret key from the public key as input and the private key on the device
	resultKey, err := p11.PrivateKey(privateKey).Derive(*mech, attrTemplate)
	if err != nil {
		panic(err)
	}
	if len(resultKey) != NoiseKeySize {
		panic(fmt.Errorf("Wrong size derived (%d)", len(resultKey)))
	}

	fmt.Printf("Derived key: %x\n", resultKey)

	session.Logout()
	session.Close()
	module.Destroy()
}
