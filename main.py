import base64
from tkinter import *
from tkinter import messagebox

#Functions
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

#save note
def save_clicked():
    entry_save = entry1.get()
    text_save = secret_text.get("1.0", END)
    master_key_save = master_key.get()

    if len(entry_save) == 0 or len(text_save) == 0 or len(master_key_save) == 0:
        messagebox.showinfo(title="Error", text="Please enter all information.")
    else:
        message_encrypted = encode(master_key_save, text_save)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f'\n{entry_save}\n{message_encrypted}')
        except FileNotFoundError:
            with open ("mysecret.txt", "w") as data_file:
                data_file.write(f'\n{entry_save}\n{message_encrypted}')
        finally:
            entry1.delete(0, END)
            secret_text.delete("1.0", END)
            master_key.delete(0, END)

def decrypt_notes():
    message_encrypted = secret_text.get("1.0", END).strip()
    master_key_save = master_key.get().strip()

    if len(message_encrypted) == 0 or len(master_key_save) == 0:
        messagebox.showinfo(title="Error!", message="Please Enter All Information")
    else:
        try:
            decrypt_message = decode(master_key_save, message_encrypted)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypt_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")
# UI
window = Tk()
window.title("Secret Notes")
window.minsize(width=300, height=600)

# image
canvas = Canvas(height=100, width=100)
logo = PhotoImage(file="top_secret.png")
logo = logo.subsample(4)   #Resmi 1/4 oranında küçülttüm
canvas.create_image((50, 50), image=logo)
canvas.pack(pady=35)

# secret title
label1 = Label(text="Enter your title")
label1.pack()
entry1 = Entry(width=30)
entry1.pack()

# title and secret note
label2 = Label(text="Enter your secret")
label2.pack()
label2.pack()
secret_text = Text(width=30, height=10)
secret_text.focus()
secret_text.pack()

# title and password
label3 = Label(text="Enter master key")
label3.pack()
label3.pack()
master_key = Entry(width=30)
master_key.pack()

# Save & Encrypt and Decrypt button
button1 = Button(text="Save & Encrypt", command=save_clicked)
button1.pack(pady=5)

button2 = Button(text="Decrypt", command=decrypt_notes)
button2.pack()

window.mainloop()
