# chordedfsk
Python script that encrypts data using AES-256-CBC, then encodes the encrypted data as audio using key-based pseudo-random frequency mapping with chorded FSK modulation
### Encrypt command arguments
| Argument       | Description                              |
| -------------- | -----------------------------------------|
| `--key`        | AES key (32 characters)                  |
| `--iv`         | Initialization vector (16 characters)    |
| `--output`     | Output audio file (.flac, .wav or .aiff) |
| `--text TEXT`  | Text to encrypt                          |
| `--file FILE`  | File to encrypt                          |
| `-h, --help`   | Show help message and exit               |
### Decrypt command arguments
| Argument       | Description                           |
| -------------- | ------------------------------------- |
| `--key`        | AES key (32 characters)               |
| `--iv`         | Initialization vector (16 characters) |
| `--input`      | Input audio file                      |
| `--file`       | Extract as file                       |
| `-h, --help`   | Show help message and exit            |
### Example commands
- encrypt text:
```
python chordedfsk.py encrypt --key MyNewSecretKeyForAES256Crypto123 --iv InitVectorAES16b --output output.flac --text "text to be encrypted"
```
- encrypt file:
```
python chordedfsk.py encrypt --key MyNewSecretKeyForAES256Crypto123 --iv InitVectorAES16b --output output.flac --file /file/path
```
- decrypt text:
```
python chordedfsk.py decrypt --key MyNewSecretKeyForAES256Crypto123 --iv InitVectorAES16b --input output.flac
```
- decrypt file:
```
python chordedfsk.py decrypt --key MyNewSecretKeyForAES256Crypto123 --iv InitVectorAES16b --input output.flac --file
```
### Notes
- Files are automatically compressed except for already compressed formats
- FLAC, WAV, and AIFF output formats are supported, but FLAC is recommended for smaller file sizes
- Please note that this project is not intended for encrypting large files, as the output audio file will be extremely large and will take a long time to process
- The encrypted hex stream is grouped into chords, where each character is mapped to a permuted note-frequency table. Multiple frequencies are played simultaneously to encode each step
### Credits
Many thanks to the developers of [NumPy](https://github.com/numpy/numpy), [SciPy](https://github.com/scipy/scipy), [SoundFile](https://github.com/bastibe/python-soundfile), [PyCryptodome](https://github.com/Legrandin/pycryptodome) and all the other modules used in this project!
### Disclaimer
This is a tool for educational / personal use only — the author is not responsible for any misuse

Shield: [![CC BY-NC-SA 4.0][cc-by-nc-sa-shield]][cc-by-nc-sa]

This work is licensed under a
[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License][cc-by-nc-sa].

[![CC BY-NC-SA 4.0][cc-by-nc-sa-image]][cc-by-nc-sa]

[cc-by-nc-sa]: http://creativecommons.org/licenses/by-nc-sa/4.0/
[cc-by-nc-sa-image]: https://licensebuttons.net/l/by-nc-sa/4.0/88x31.png
[cc-by-nc-sa-shield]: https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg
