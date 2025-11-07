# Task 2: Image Encryption with ECB vs CBC Mode

This task demonstrates the visual difference between encrypting an image using ECB (Electronic Code Book) and CBC (Cipher Block Chaining) modes with AES-128 encryption, highlighting why ECB is insecure for many data types.

---

## Commands Used for Image Encryption

### 1. ECB Mode
  **Encryption**
  ```console
  openssl enc -aes-128-ecb -e -in pic_original.bmp -out pic_ecb.bmp -K 00112233445566778889aabbccddeeff
  ```
### 2. CBC Mode
  **Encryption**
  ```console
  openssl enc -aes-128-cbc -e -in pic_original.bmp -out pic_cbc.bmp -K 00112233445566778889aabbccddeeff -iv 0102030405060708
  ```
---

## Header Replacement Process
After encryption, the image headers need to be replaced with the original header to make the images viewable.

- Open the original image in GHex:
  ```console
  ghex pic_original.bmp &
  ```
- Select the first 54 bytes (the header) and copy them.
- Open the encrypted image (e.g., pic_ecb.bmp) in GHex:
  ```console
  ghex pic_ecb.bmp &
  ```
- Click on the first byte, go to Edit -> Paste, and save the file.
- Repeat the process for the CBC-encrypted image (pic_cbc.bmp).
