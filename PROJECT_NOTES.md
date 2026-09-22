# Project Notes / Viva Preparation

## Title
Secure Data Hiding Using Steganography

## Objective
To protect a confidential text message by encrypting it first and then
concealing the encrypted data inside an image.

## Modules
1. Home
2. Sender Side / Encryption
3. Receiver Side / Decryption
4. Cryptographic layer
5. Steganography layer
6. File handling

## Why LSB?
The least significant bit of a color channel can be changed with a very
small visual difference. The project uses the LSB of RGB channels to store
the encrypted payload.

## Why PNG?
PNG is lossless. JPEG is lossy and can alter pixel values during
compression, which may destroy hidden LSB data.

## Why encryption + steganography?
Steganography hides the existence of the message. Encryption protects the
message contents if someone manages to extract the hidden data.

## Important viva questions
- What is steganography?
- What is the difference between encryption and steganography?
- What is LSB?
- Why is PNG preferred for the encoded image?
- What is AES-GCM?
- What is Base64 and why is it used here?
- What are Prime 1 and Prime 2 used for in this implementation?
- What happens if the wrong password is entered?
- What happens if the encoded image is modified?
- Why is a payload-length header needed?
