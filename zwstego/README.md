# zwstego
Python script that encodes data into zero‑width Unicode characters, with optional AES encryption and file support
### Encode command arguments
| Argument       | Description                               |
| -------------- | ----------------------------------------- |
| `-t, --text`   | Text to encode                            |
| `-f, --file`   | File to encode                            |
| `-k, --key`    | AES key (32 bytes)                        |
| `-i, --iv`     | Initialization vector (16 bytes)          |
| `-b, --bin`    | Use 2‑char mode                           |
| `-o, --output` | Output file (if omitted, print to stdout) |
| `-h, --help`   | Show help message and exit                |

### Decode command arguments
| Argument       | Description                                           |
| -------------- | ----------------------------------------------------- |
| `input`        | File containing invisible characters                  |
| `-k, --key`    | AES key (32 bytes)                                    |
| `-i, --iv`     | Initialization vector (16 bytes)                      |
| `-b, --bin`    | Use 2‑char mode (must match encoding)                 |
| `-f, --file`       | Extract as file (requires embedded name)              |
| `-o, --output` | Output file (for text) or override filename for files |
| `-h, --help`   | Show help message and exit                            |

### Example commands
#### Encode
- encode text:
```
python zwstego.py encode --text "TEXT" --output OUTPUT_FILE
```
- encrypt and encode text:
```
python zwstego.py encode --text "TEXT" --key KEY --iv IV --output OUTPUT_FILE
```
- encode file:
```
python zwstego.py encode --file FILE --output OUTPUT_FILE
```
- encrypt and encode file:
```
python zwstego.py encode --file FILE --key KEY --iv IV --output OUTPUT_FILE
```
#### Decode
- decode text:
```
python zwstego.py decode INPUT_FILE
```
- decrypt and decode text:
```
python zwstego.py decode INPUT_FILE --key KEY --iv IV
```
- decode file:
```
python zwstego.py decode INPUT_FILE --file
```
- decrypt and decode file:
```
python zwstego.py decode INPUT_FILE --key KEY --iv IV --file
```
### Notes
- Files are automatically compressed before encryption except for already compressed formats
- The 2‑character mode (`--bin`) uses U+2060 (Word Joiner) for bit 0 and U+200D (Zero Width Joiner) for bit 1
- The decoder ignores any visible text around the invisible characters, so the encoded string can be embedded in tweets or messages
- KEY must be exactly 32 bytes (example: `X9fK2mP8qR4tY7wZ3nB6cD1eF0g2jKLm`) and IV 16 bytes (example: `A1b2C3d4E5f6G7h8`)
### Credits
Many thanks to the developers of [PyCryptodome](https://github.com/Legrandin/pycryptodome), [python-lzma](https://docs.python.org/3/library/lzma.html) and all the other modules used in this project!
### Disclaimer
This is a tool for educational / personal use only — the author is not responsible for any misuse

Shield: [![CC BY-NC-SA 4.0][cc-by-nc-sa-shield]][cc-by-nc-sa]

This work is licensed under a
[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License][cc-by-nc-sa].

[![CC BY-NC-SA 4.0][cc-by-nc-sa-image]][cc-by-nc-sa]

[cc-by-nc-sa]: http://creativecommons.org/licenses/by-nc-sa/4.0/
[cc-by-nc-sa-image]: https://licensebuttons.net/l/by-nc-sa/4.0/88x31.png
[cc-by-nc-sa-shield]: https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg
