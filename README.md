# File-Encryption-Application
This is a Java program that encrypts and decrypts text or binary files using the Data Encryption Standard (DES).

## Additional Libraries Needed to Run This Program
- JavaFX: https://openjfx.io/
- SQLite for Java: https://github.com/xerial/sqlite-jdbc/releases

## How to Run
- Import necessary libraries
- Select mode: Encrypt or Decrypt
- Enter the path of the file you'd like to encrypt or the encrypted file you'd like to decrypt (include .txt for text files and .bin for binary files)
- Click "Generate Random Key" or provide your own 16 character hex key
- Enter path (including name) of the newly outputted file
- Click "Run" to run selected action
- Check ouput box to see if the process was successful

## User Interface (JavaFX)
The main class creates a graphical interface using JavaFX. It includes buttons, text fields, and a mode selector. When the user clicks "Run", the input is validated and passed to the DES processing class.

## Processing Layer
The main class handles all primary functions:
- Reads and writes files
- Converts the key from hexadecimal to a 64-bit long value
- Chooses between the encryption and decryption modules

## Cryptographic Core
The cryptographic logic follows the original DES algorithm:
- Encryption: Adds PKCS#7 padding to make ensure 8-byte blocks. Uses 16 Feistel rounds, each applying S-box substitution, permutation, and XOR operations
- Decryption: Reverses the subkey order to decrypt, then removes padding
- Key generator: Produces 16 subkeys fromt he main 64-bit key using PC-1, PC-2, and rotation tables. The algorithm structure guarantees a one-to-one mapping between plaintext and ciphertext, reversible only with the correct key.

Data flow summary:
- The user enters the file paths, mode, and key
- Input bytes are read from disk
- Depending on the mode selected, the system encrypts or decrypts in 64-bit chunks
- The processed bytes are written to the output file
- A status message confirms completion or error



