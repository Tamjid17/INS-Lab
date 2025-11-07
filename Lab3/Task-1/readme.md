# Commands used for AES Encryption

## 1. CBC Mode
- Encryption
```console
openssl enc -aes-128-cbc -e -in plaintext.txt -out cipher-cbc.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
```

- Decryption
```console
openssl enc -aes-128-cbc -d -in cipher-cbc.bin -out decrypted-cbc.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
```
---
## 2. CFB Mode
- Encryption
```console
openssl enc -aes-128-cfb -e -in plaintext.txt -out cipher-cfb.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
```
- Decryption
```console
openssl enc -aes-128-cfb -d -in cipher-cfb.bin -out decrypted-cfb.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
```
---
## 3. OFB Mode
- Encryption
```console
openssl enc -aes-128-ofb -e -in plaintext.txt -out cipher-ofb.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
```
- Decryption
```console
openssl enc -aes-128-ofb -d -in cipher-ofb.bin -out decrypted-ofb.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
```
