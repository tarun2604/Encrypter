import tkinter as tk
from tkinter import ttk
import sqlite3
from tkinter import PhotoImage
from tkinter import Label
from tkinter import simpledialog, messagebox

from sklearn.model_selection import train_test_split

MORSE_CODE_DICT = {'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
                   'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
                   'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
                   'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....',
                   '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----', ' ': '/'}

conn = sqlite3.connect('encryption_results.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS results
             (id INTEGER PRIMARY KEY AUTOINCREMENT, 
              input_text TEXT, 
              encrypted_text TEXT, 
              decrypted_text TEXT,
              encryption_type TEXT)''')

conn.commit()

def insert_into_db(input_text, encrypted_text, decrypted_text, encryption_type):
    c.execute("INSERT INTO results (input_text, encrypted_text, decrypted_text, encryption_type) VALUES (?, ?, ?, ?)",
              (input_text, encrypted_text, decrypted_text, encryption_type))
    conn.commit()


def display_results():
    result_window = tk.Toplevel(root)
    result_window.title("Encrypted and Decrypted Results")

    c.execute("SELECT * FROM results")
    results = c.fetchall()

    for result in results:
        result_text = f"Original Text: {result[1]}\nEncrypted Text: {result[2]}\nDecrypted Text: {result[3]}\nEncryption Type: {result[4]}\n\n"
        result_label = tk.Label(result_window, text=result_text)
        result_label.pack()


def create_frame(parent, row, column, padx=5, pady=5):
    frame = ttk.Frame(parent)
    frame.grid(row=row, column=column, padx=padx, pady=pady)
    return frame


def create_button(parent, text, command, row, column, width=15, height=3, padx=5, pady=5):
    button = tk.Button(parent, text=text, command=command, bg="#85CD32", width=width, height=height)
    button.grid(row=row, column=column, padx=padx, pady=pady)


def create_label(parent, text, row, column, padx=5, pady=5):
    label = tk.Label(parent, text=text)
    label.grid(row=row, column=column, padx=padx, pady=pady)


def create_text(parent, height, width, row, column, padx=5, pady=5):
    text = tk.Text(parent, height=height, width=width)
    text.grid(row=row, column=column, padx=padx, pady=pady)
    return text

def create_lime_green_heading(parent, text, row, column, pady=5):
    heading_label = tk.Label(parent, text=text, font=('Helvetica', 16, 'bold'), bg="#85CD32", padx=10, pady=10, fg="white")
    heading_label.grid(row=row, column=column, pady=pady, sticky='nsew')
    parent.columnconfigure(0, weight=1)  
    return heading_label



def morse_gui():
    morse_window = tk.Toplevel(root)
    morse_window.title("Morse Code Encryption")

    frame = create_frame(morse_window, 0, 0)
    create_label(frame, "Input:", 0, 0)
    input_text = create_text(frame, 5, 30, 0, 1)
    create_button(frame, "Encode", lambda: encode(input_text), 1, 0)
    create_button(frame, "Decode", lambda: decode(input_text), 1, 1)
    create_label(frame, "Output:", 2, 0)
    output_text = create_text(frame, 5, 30, 2, 1)

    def encode(text):
        encoded_text = text_to_morse(text.get("1.0", "end-1c"))
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encoded_text)
        insert_into_db(text.get("1.0", "end-1c"), encoded_text, "", "Morse Code")

    def decode(text):
        morse_code = text.get("1.0", "end-1c")
        decoded_text = morse_to_text(morse_code)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", decoded_text)
        insert_into_db("", morse_code, decoded_text, "Morse Code")


def caesar_gui():
    caesar_window = tk.Toplevel(root)
    caesar_window.title("Caesar Cipher")

    frame = create_frame(caesar_window, 0, 0)
    create_label(frame, "Input:", 0, 0)
    input_text = create_text(frame, 5, 30, 0, 1)
    create_label(frame, "Shift Key:", 1, 0)
    key_entry = ttk.Entry(frame)
    key_entry.grid(row=1, column=1, padx=5, pady=5)
    create_button(frame, "Encrypt/Decrypt", lambda: encrypt_decrypt(input_text, key_entry), 2, 0)
    create_label(frame, "Output:", 3, 0)
    output_text = create_text(frame, 5, 30, 3, 1)

    def encrypt_decrypt(text, key_entry):
        shift = int(key_entry.get())
        encrypted_text = caesar_cipher(text.get("1.0", "end-1c"), shift)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encrypted_text)
        insert_into_db(text.get("1.0", "end-1c"), encrypted_text, "", "Caesar Cipher")


def vigenere_gui():
    vigenere_window = tk.Toplevel(root)
    vigenere_window.title("Vigenère Cipher")

    frame = create_frame(vigenere_window, 0, 0)
    create_label(frame, "Input:", 0, 0)
    input_text = create_text(frame, 5, 30, 0, 1)
    create_label(frame, "Key:", 1, 0)
    key_entry = ttk.Entry(frame)
    key_entry.grid(row=1, column=1, padx=5, pady=5)
    create_button(frame, "Encrypt", lambda: encrypt_action(input_text, key_entry), 2, 0)
    create_button(frame, "Decrypt", lambda: decrypt_action(input_text, key_entry), 2, 1)
    create_label(frame, "Output:", 3, 0)
    output_text = create_text(frame, 5, 30, 3, 1)

    def encrypt_action(text, key_entry):
        key = key_entry.get()
        encrypted_text = vigenere_encrypt(text.get("1.0", "end-1c"), key)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", f"Encrypted Text: {encrypted_text}")
        insert_into_db(text.get("1.0", "end-1c"), encrypted_text, "", "Vigenere Cipher")

    def decrypt_action(text, key_entry):
        key = key_entry.get()
        decrypted_text = vigenere_decrypt(text.get("1.0", "end-1c"), key)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", f"Decrypted Text: {decrypted_text}")
        insert_into_db("", "", decrypted_text, "Vigenere Cipher")


def atbash_gui():
    atbash_window = tk.Toplevel(root)
    atbash_window.title("Atbash Cipher")

    frame = create_frame(atbash_window, 0, 0)
    create_label(frame, "Input:", 0, 0)
    input_text = create_text(frame, 5, 30, 0, 1)
    create_button(frame, "Encrypt/Decrypt", lambda: encrypt_decrypt(input_text), 1, 0)
    create_label(frame, "Output:", 2, 0)
    output_text = create_text(frame, 5, 30, 2, 1)

    def encrypt_decrypt(text):
        encrypted_text = atbash_cipher(text.get("1.0", "end-1c"))
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encrypted_text)
        insert_into_db(text.get("1.0", "end-1c"), encrypted_text, "", "Atbash Cipher")


def polybius_gui():
    polybius_window = tk.Toplevel(root)
    polybius_window.title("Polybius Square Cipher")

    frame = create_frame(polybius_window, 0, 0)
    create_label(frame, "Input:", 0, 0)
    input_text = create_text(frame, 5, 30, 0, 1)
    create_button(frame, "Encode", lambda: encode(input_text), 1, 0)
    create_button(frame, "Decode", lambda: decode(input_text), 1, 1)
    create_label(frame, "Output:", 2, 0)
    output_text = create_text(frame, 5, 30, 2, 1)

    def encode(text):
        plaintext = text.get("1.0", "end-1c")
        polybius_square = create_polybius_square()
        encoded_text = encode_polybius_square(polybius_square, plaintext)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encoded_text)
        insert_into_db(plaintext, encoded_text, "", "Polybius Cipher")

    def decode(text):
        encoded_text = text.get("1.0", "end-1c")
        polybius_square = create_polybius_square()
        decoded_text = decode_polybius_square(polybius_square, encoded_text)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", decoded_text)
        insert_into_db("", encoded_text, decoded_text)


def ascii_gui():
    ascii_window = tk.Toplevel(root)
    ascii_window.title("ASCII Translator")

    frame = create_frame(ascii_window, 0, 0)
    create_label(frame, "Input:", 0, 0)
    input_text = create_text(frame, 5, 30, 0, 1)
    create_button(frame, "Text to ASCII", lambda: text_to_ascii_action(input_text), 1, 0)
    create_button(frame, "ASCII to Text", lambda: ascii_to_text_action(input_text), 1, 1)
    create_label(frame, "Output:", 2, 0)
    output_text = create_text(frame, 5, 30, 2, 1)

    def text_to_ascii_action(text):
        input_text = text.get("1.0", "end-1c")
        ascii_art = text_to_ascii(input_text)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", ascii_art)
        insert_into_db(input_text, ascii_art, "", "Text to Ascii")

    def ascii_to_text_action(text):
        ascii_art = text.get("1.0", "end-1c")
        input_text = ascii_to_text(ascii_art)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", input_text)
        insert_into_db("", ascii_art, input_text, "Ascii to Text")


def rail_fence_gui():
    rail_fence_window = tk.Toplevel(root)
    rail_fence_window.title("Rail Fence Cipher")

    frame = create_frame(rail_fence_window, 0, 0)
    create_label(frame, "Input:", 0, 0)
    input_text = create_text(frame, 5, 30, 0, 1)
    create_label(frame, "Number of Rails:", 1, 0)
    rails_entry = ttk.Entry(frame)
    rails_entry.grid(row=1, column=1, padx=5, pady=5)
    create_button(frame, "Encrypt", lambda: encrypt(input_text, rails_entry), 2, 0)
    create_button(frame, "Decrypt", lambda: decrypt(input_text, rails_entry), 2, 1)
    create_label(frame, "Output:", 3, 0)
    output_text = create_text(frame, 5, 30, 3, 1)

    def encrypt(text, rails_entry):
        plaintext = text.get("1.0", "end-1c")
        rails = int(rails_entry.get())
        encrypted_text = rail_fence_encrypt(plaintext, rails)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encrypted_text)
        insert_into_db
        insert_into_db(plaintext, encrypted_text, "", "Railfence Encryption")

    def decrypt(text, rails_entry):
        encrypted_text = text.get("1.0", "end-1c")
        rails = int(rails_entry.get())
        decrypted_text = rail_fence_decrypt(encrypted_text, rails)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", decrypted_text)
        insert_into_db("", encrypted_text, decrypted_text, "Railfence Decryption")


def text_to_morse(text):
    morse_code = ''
    for char in text.upper():
        if char in MORSE_CODE_DICT:
            morse_code += MORSE_CODE_DICT[char] + ' '
        else:
            morse_code += '/ '
    return morse_code


def morse_to_text(morse_code):
    morse_code = morse_code.strip().split(' ')
    text = ''
    for code in morse_code:
        for key, value in MORSE_CODE_DICT.items():
            if code == value:
                text += key
    return text


def caesar_cipher(text, shift):
    result = ''
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result


def vigenere_encrypt(plain_text, key):
    result = ''
    key = key.upper()
    key_index = 0
    for char in plain_text:
        if char.isalpha():
            ascii_offset = ord('A')
            key_char = key[key_index]
            key_offset = ord(key_char)
            result += chr((ord(char) + key_offset - 2 * ascii_offset) % 26 + ascii_offset)
            key_index = (key_index + 1) % len(key)
        else:
            result += char
    return result


def vigenere_decrypt(cipher_text, key):
    result = ''
    key = key.upper()
    key_index = 0
    for char in cipher_text:
        if char.isalpha():
            ascii_offset = ord('A')
            key_char = key[key_index]
            key_offset = ord(key_char)
            result += chr((ord(char) - key_offset) % 26 + ascii_offset)
            key_index = (key_index + 1) % len(key)
        else:
            result += char
    return result


def atbash_cipher(text):
    result = ''
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((25 - (ord(char) - ascii_offset)) + ascii_offset)
        else:
            result += char
    return result


def create_polybius_square():
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    polybius_square = [['' for _ in range(5)] for _ in range(5)]
    key = "KEYWORD"
    key += alphabet
    key = ''.join(sorted(set(key), key=key.find))
    for row in range(5):
        for col in range(5):
            polybius_square[row][col] = key[0]
            key = key[1:]
    return polybius_square


def encode_polybius_square(square, text):
    result = ''
    text = text.upper().replace('J', 'I')
    for char in text:
        for row in range(5):
            if char in square[row]:
                col = square[row].index(char)
                result += str(row + 1) + str(col + 1)
    return result


def decode_polybius_square(square, text):
    result = ''
    for i in range(0, len(text), 2):
        row = int(text[i]) - 1
        col = int(text[i + 1]) - 1
        result += square[row][col]
    return result


def text_to_ascii(text):
    ascii_art = ''
    for char in text:
        ascii_value = ord(char)
        if char.isalpha():
            ascii_art += f'{char}: {ascii_value}\n'
        else:
            ascii_art += f'\'{char}\': {ascii_value}\n'
    return ascii_art


def ascii_to_text(ascii_art):
    lines = ascii_art.strip().split('\n')
    text = ''
    for line in lines:
        parts = line.split(':')
        if len(parts) == 2:
            text += chr(int(parts[1].strip()))
        elif len(parts) == 1 and parts[0].strip():
            text += parts[0].strip()
    return text


def rail_fence_encrypt(text, rails):
    fence = [''] * rails
    index = 0
    for char in text:
        if char.isalpha():
            fence[index] += char
            index = (index + 1) % rails
    return ''.join(fence)


def rail_fence_decrypt(text, rails):
    fence = [''] * rails
    index = 0
    for char in text:
        if char.isalpha():
            fence[index] += 'X'
            index = (index + 1) % rails
    return ''.join(fence)

def rot13_cipher(text):
    result = ''
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset + 13) % 26 + ascii_offset)
        else:
            result += char
    return result

def rot13_gui():
    rot13_window = tk.Toplevel(root)
    rot13_window.title("ROT13 Cipher")

    frame = create_frame(rot13_window, 0, 0)
    create_label(frame, "Input:", 0, 0)
    input_text = create_text(frame, 5, 30, 0, 1)
    create_button(frame, "Encrypt/Decrypt", lambda: encrypt_decrypt_rot13(input_text), 1, 0)
    create_label(frame, "Output:", 2, 0)
    output_text = create_text(frame, 5, 30, 2, 1)

    def encrypt_decrypt_rot13(text):
        result = rot13_cipher(text.get("1.0", "end-1c"))
        output_text.delete("1.0", "end")
        output_text.insert("1.0", result)
        insert_into_db(text.get("1.0", "end-1c"), result, "", "ROT13 Cipher")


def save_rail_fence_results(plaintext, encrypted_text):
    insert_into_db(plaintext, encrypted_text, "")

def rail_fence_gui():
    rail_fence_window = tk.Toplevel(root)
    rail_fence_window.title("Rail Fence Cipher")

    frame = create_frame(rail_fence_window, 0, 0)
    create_label(frame, "Input:", 0, 0)
    input_text = create_text(frame, 5, 30, 0, 1)
    create_label(frame, "Number of Rails:", 1, 0)
    rails_entry = ttk.Entry(frame)
    rails_entry.grid(row=1, column=1, padx=5, pady=5)
    create_button(frame, "Encrypt", lambda: encrypt(input_text, rails_entry), 2, 0)
    create_button(frame, "Decrypt", lambda: decrypt(input_text, rails_entry), 2, 1)
    create_label(frame, "Output:", 3, 0)
    output_text = create_text(frame, 5, 30, 3, 1)

    def encrypt(text, rails_entry):
        plaintext = text.get("1.0", "end-1c")
        rails = int(rails_entry.get())
        encrypted_text = rail_fence_encrypt(plaintext, rails)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encrypted_text)
        save_rail_fence_results(plaintext, encrypted_text)

    def decrypt(text, rails_entry):
        encrypted_text = text.get("1.0", "end-1c")
        rails = int(rails_entry.get())
        decrypted_text = rail_fence_decrypt(encrypted_text, rails)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", decrypted_text)
        save_rail_fence_results("", encrypted_text)

user_databases = {}

def save_credentials(username, password):
    if username not in user_databases:
        user_databases[username] = {'password': password, 'other_data': None}
        messagebox.showinfo("Sign Up", "User successfully signed up!")
    else:
        messagebox.showinfo("Sign Up", "User with this username already exists.")

def check_credentials(username, password):
    return username in user_databases and user_databases[username]['password'] == password

def get_user_data(username):
    return user_databases.get(username, None)


root = tk.Tk()
root.title("Multi-Encryption Tool")

menu_bar = tk.Menu(root)
root.config(menu=menu_bar)


file_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Exit", command=root.destroy)


main_frame = create_frame(root, 0, 0)
create_lime_green_heading(main_frame, "Welcome to Multi Encryption-Decryption tool", 0, 0, pady=10)
encryption_image = PhotoImage(file='encryption.png')
lbl = Label(main_frame, image=encryption_image)
lbl.grid(row=1, column=0)

encryption_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Encryption", menu=encryption_menu)
encryption_menu.add_command(label="Morse Code", command=morse_gui)
encryption_menu.add_command(label="Caesar Cipher", command=caesar_gui)
encryption_menu.add_command(label="Vigenère Cipher", command=vigenere_gui)
encryption_menu.add_command(label="Atbash Cipher", command=atbash_gui)
encryption_menu.add_command(label="Polybius Square Cipher", command=polybius_gui)
encryption_menu.add_command(label="ASCII Translator", command=ascii_gui)
encryption_menu.add_command(label="Rail Fence Cipher", command=rail_fence_gui)
encryption_menu.add_command(label="ROT13 Cipher", command=rot13_gui)

results_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Results", menu=results_menu)
results_menu.add_command(label="Display Results", command=display_results)

root.mainloop()