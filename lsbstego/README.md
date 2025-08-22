A Python script that encrypts a message using AES-256-CBC, then hides the encrypted data inside an image’s pixels using key-based pseudo-random positions for LSB steganography, allowing secure message embedding and extraction with matching keys and markers

- hide:
```
python lsbstego.py hide cat.png "hidden text in the image" MyNewSecretKeyForAES256Crypto123 InitVectorAES16b 011100110111010001100001011100100111010001101101011000010111001001101011 01100101011011100110010001101101011000010111001001101011 output.png
```
- extract:
```
python lsbstego.py extract output.png MyNewSecretKeyForAES256Crypto123 InitVectorAES16b 011100110111010001100001011100100111010001101101011000010111001001101011 01100101011011100110010001101101011000010111001001101011
```

## results:
original png:

![pic](cat.png)

png with hidden encrypted msg:

![pic1](output.png)
