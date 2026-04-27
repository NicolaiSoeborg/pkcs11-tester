# pkcs11-tester

```bash
go run main.go /usr/lib64/opensc-pkcs11.so

go build
./pkcs11-tester /usr/lib64/opensc-pkcs11.so
```

This will connect to a PKCS#11 token using the provided library, it will then open a session to _slot_ 0 (edit the code to change) and login using PIN from stdin.

If login is successful, it will search for a key with these properties:

|Property                | Value     |
| ---------------------- | --------- |
|`CKA_EC_PARAMS`         |`id-X25519`|
|`CKA_CLASS`             |`CKO_PRIVATE_KEY`|
|`CKA_ALLOWED_MECHANISMS`|`CKM_ECDH1_DERIVE`|
|`CKA_DERIVE`            |true|
|`CKA_TOKEN`             |true|

If such an object is found, it will try to find the corresponding public key having these values:

|Property                | Value     |
| ---------------------- | --------- |
|`CKA_EC_PARAMS`         |`id-X25519`|
|`CKA_CLASS`             |`CKO_PUBLIC_KEY`|
|`CKA_TOKEN`             |true|
|`CKA_ID`                | {value from private key, probably blank} |

If both private and public key is found, then public key will be printed (base64 encoded) and to check that `CKM_ECDH1_DERIVE` works, the tool will derive a shared secret using `ECDH(secret, public)`
