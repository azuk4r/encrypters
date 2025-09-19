Python script that encrypts a message using AES-256-CBC, then hides the encrypted data inside an image's pixels using key-based pseudo-random positions for LSB steganography
### Hide command arguments
| Argument       | Description                               |
| -------------- | ----------------------------------------- |
| `image`        | Path to the image file                    |
| `key`          | AES key (32 characters)                   |
| `iv`           | Initialization vector (16 characters)     |
| `start_marker` | Start marker (binary string)              |
| `end_marker`   | End marker (binary string)                |
| `message`      | Message to hide                           |
| `output`       | Output image path (default: `output.png`) |
| `-h, --help`   | Show help message and exit                |
### Extract command arguments
| Argument       | Description                           |
| -------------- | ------------------------------------- |
| `image`        | Path to the image file                |
| `key`          | AES key (32 characters)               |
| `iv`           | Initialization vector (16 characters) |
| `start_marker` | Start marker (binary string)          |
| `end_marker`   | End marker (binary string)            |
| `-h, --help`   | Show help message and exit            |
### Example commands
- hide:
```
python lsbstego.py hide cat.png MyNewSecretKeyForAES256Crypto123 InitVectorAES16b 011100110111010001100001011100100111010001101101011000010111001001101011 01100101011011100110010001101101011000010111001001101011 "hidden text in the image" output.png
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
