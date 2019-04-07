# filecrypt
## Summary

filecrypt - A simple tool for encrypt/decrypt files with user supplied password. Without the right password the file can't be decrypted.
## Usage
```c
usage: ./filecrypt [-e|-d] [-r] [-p password] [-h] path
  -e        encrypt the files in the path
  -d        decrypt the files in the path
  -r        recursive the path
  -p        password to encrypt or decrypt
  -h        show this usage
```
## File encrypt/decrypt algorithms
1. XOR
2. DES (TODO ...)
3. ...
## Compile
Just execute "make" in this path.
## Timeline
```c
2019-04-07  first commit
```
