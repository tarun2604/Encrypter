# Encryption Tool using Tkinter and SQLite

## Overview
This is a Python-based encryption and decryption tool with a graphical user interface (GUI) built using Tkinter. It supports multiple encryption algorithms, allowing users to encrypt and decrypt text using various ciphers. The application also includes a database feature to store encryption results.

## Features
- **Supported Ciphers:**
  - Morse Code
  - Caesar Cipher
  - Vigenère Cipher
  - Atbash Cipher
  - Polybius Square Cipher
- **User-Friendly Interface:**
  - Encrypt and decrypt text easily with a Tkinter-based GUI.
- **Database Storage:**
  - Stores encryption results in an SQLite database for future reference.

## Requirements
Ensure you have the following installed:
- Python 3.x
- Tkinter (included with Python)
- SQLite3 (included with Python)

## Installation
1. Clone the repository or download the script files.
   ```bash
   git clone https://github.com/your-repo/encryption-tool.git
   cd encryption-tool
   ```
2. Install required dependencies (if any):
   ```bash
   pip install tk
   ```
3. Run the application:
   ```bash
   python encryption_tool.py
   ```

## Usage
1. Open the application.
2. Enter the text to encrypt or decrypt.
3. Select the encryption method.
4. Click the **Encrypt** or **Decrypt** button.
5. View the results in the application.
6. The encrypted data will be stored in the SQLite database.

## Cipher Explanations
- **Morse Code:** Converts text to and from Morse code.
- **Caesar Cipher:** A shift cipher where letters are shifted by a fixed amount.
- **Vigenère Cipher:** A polyalphabetic substitution cipher using a key.
- **Atbash Cipher:** A simple substitution cipher that reverses the alphabet.
- **Polybius Square Cipher:** A cipher that replaces each letter with coordinates in a 5x5 grid.

## Database Structure
The application uses SQLite to store encrypted messages. The database schema includes:
- `id` (Primary Key)
- `original_text` (Text before encryption)
- `encrypted_text` (Result after encryption)
- `cipher_used` (Type of cipher used)

## Future Improvements
- Add more encryption algorithms.
- Implement a user authentication system.
- Enhance the UI with modern design elements.

## License
This project is open-source and available under the MIT License.

## Contributing
If you'd like to contribute:
1. Fork the repository.
2. Create a new branch.
3. Make your changes and commit them.
4. Submit a pull request.

## Contact
For any questions or suggestions, feel free to reach out or open an issue in the repository.

---

Enjoy encrypting and decrypting with this tool!

