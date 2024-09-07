from tkinter import *
import base64
from tkinter import messagebox

# Define a constant for the password
PASSWORD = "1234"  # The password required for encryption and decryption

def verify_password():
    """Verify the entered password."""
    password = password_entry.get().strip()
    if password == PASSWORD:
        return True
    else:
        messagebox.showwarning("Password Error", "Incorrect password.")
        return False

def encrypt_text():
    """Encrypt the text from the text box using the secret key."""
    input_text = text1.get("1.0", END).strip()
    secret_key = password_entry.get().strip()
    
    if input_text and secret_key and verify_password():
        encrypted = base64.b64encode((input_text + secret_key).encode()).decode()
        messagebox.showinfo("Encrypted Text", encrypted)
    else:
        messagebox.showwarning("Input Error", "Please enter text and a secret key to encrypt.")

def decrypt_text():
    """Decrypt the text from the text box using the secret key."""
    input_text = text1.get("1.0", END).strip()
    secret_key = password_entry.get().strip()
    
    if input_text and secret_key and verify_password():
        try:
            decrypted = base64.b64decode(input_text.encode()).decode()
            decrypted = decrypted.replace(secret_key, "")
            messagebox.showinfo("Decrypted Text", decrypted)
        except (base64.binascii.Error, UnicodeDecodeError):
            messagebox.showerror("Decryption Error", "Invalid input for decryption.")
    else:
        messagebox.showwarning("Input Error", "Please enter text and a secret key to decrypt.")

def reset_fields():
    """Clear the text fields."""
    text1.delete("1.0", END)  # Clear the text box
    code.set("")  # Clear the entry field
    password_entry.delete(0, END)  # Clear the password entry field

def main_screen():
    screen = Tk() 
    screen.geometry("375x450")  # Adjusted height for password entry
    screen.title("Encryption and Decryption App")
    
    label = Label(screen, text="Enter text for encryption and decryption", fg="black", font=("calibri", 13))
    label.pack(pady=20)
    
    global text1
    text1 = Text(screen, font=("Roboto", 20), bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, width=355, height=100)  # Adjust height for better layout

    # Entry field for secret key (remains for functionality)
    global code
    code = StringVar()
    entry = Entry(screen, textvariable=code)


    # Label for password
    password_label = Label(screen, text="Enter password for encryption/decryption", fg="black", font=("calibri", 13))
    password_label.place(x=10, y=240)

    # Entry field for password
    global password_entry
    password_entry = Entry(screen, width=19, bd=0, font=("Arial", 25), show="*")
    password_entry.place(x=10, y=280)

    # Buttons for encryption and decryption
    button_encrypt = Button(screen, text="ENCRYPT", height=2, width=23, bg="#ed3833", fg="white", bd=0, command=encrypt_text)
    button_encrypt.place(x=10, y=320)

    button_decrypt = Button(screen, text="DECRYPT", height=2, width=23, bg="#00bd56", fg="white", bd=0, command=decrypt_text)
    button_decrypt.place(x=200, y=320)

    # RESET Button
    button_reset = Button(screen, text="RESET", height=2, width=50, bg="#1089ff", fg="white", bd=0, command=reset_fields)
    button_reset.place(x=10, y=370)

    screen.mainloop()

# Call the main_screen function to run the application
main_screen()
