# filecrypt
## Summary

filecrypt - A simple tool to encrypt/decrypt files with user supplied password. Without the right password the files can't be decrypted.
## Usage
```c
usage: filecrypt [-e|-d] [-r] [-p password] [-a algorithm] [-h] path
  -e        encrypt the files in the path
  -d        decrypt the files in the path
  -r        recursive the path
  -p        password to encrypt or decrypt
  -a        select algorithm to encrypt and decrypt the files which encrypted by it
            supported algorithms: [xor, aes], xor is default
  -h        show this usage
```
## File encrypt/decrypt algorithms
1. XOR
2. AES
3. ...

## TODO
Using multiple thread to speed up the encryption and decryption.
## Compile
Execute "make" in the root directory.
## Timeline
```c
2019-04-07  first commit
2019-04-13  add aes supported and fix the security issue
```
