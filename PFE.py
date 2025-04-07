import tkinter as tk
import customtkinter as ctk
from Crypto.Cipher import AES  # Import AES from PyCryptodome
import os  # Used for generating random keys and nonces for the statistics
import binascii
import matplotlib.pyplot as plt
import time
import socket
from tkinter import messagebox
import threading

# Global variables to store encryption results
global_key = None
global_iv = None
global_ciphertext = None

# Reset function to initialize text_area and text_area2
def reset():
    text_area.delete("1.0", tk.END)
    text_area.insert("1.0", "Enter your text here...")
    text_area.configure(text_color="gray")

    text_area2.configure(state="normal")
    text_area2.delete("1.0", "end")
    text_area2.configure(state="disabled")

    key_area.delete("1.0", "end")
    key_area.insert("1.0", "Enter your key here...")
    key_area.configure(text_color="gray")

    iv_area.delete("1.0", "end")
    iv_area.insert("1.0", "Enter your iv here...")
    iv_area.configure(text_color="gray")

    stats_area.configure(state="normal")
    stats_area.delete("1.0", "end")
    stats_area.configure(state="disabled")
   

# Placeholder logic for text area
def add_placeholder(event=None):
    if text_area.get("1.0", "end-1c") == "":
        text_area.insert("1.0", "Enter your text here...")
        text_area.configure(text_color="white")
    if key_area.get("1.0", "end-1c") == "":
        key_area.insert("1.0", "Enter your key here...")
        key_area.configure(text_color="white")
    if iv_area.get("1.0", "end-1c") == "":
        iv_area.insert("1.0", "Enter your iv here...")
        iv_area.configure(text_color="white")

def remove_placeholder(event=None):
    if text_area.get("1.0", "end-1c") == "Enter your text here...":
        text_area.delete("1.0", "end")
        text_area.configure(text_color="white")
    if key_area.get("1.0", "end-1c") == "Enter your key here...":
        key_area.delete("1.0", "end")
        key_area.configure(text_color="white")
    if iv_area.get("1.0", "end-1c") == "Enter your iv here...":
        iv_area.delete("1.0", "end")
        iv_area.configure(text_color="white")

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def increment_counter(counter):
    counter_int = int.from_bytes(counter, byteorder='big') + 1
    return counter_int.to_bytes(len(counter), byteorder='big')

def aes_ctr_encrypt(plaintext, key, nonce):
    aes_ecb = AES.new(key, AES.MODE_ECB)
    block_size = AES.block_size
    counter = nonce + b'\x00' * 8
    ciphertext = b""
    for i in range(0, len(plaintext), block_size):
        keystream = aes_ecb.encrypt(counter)
        block = plaintext[i:i + block_size]
        ciphertext += xor_bytes(block, keystream[:len(block)])
        counter = increment_counter(counter)
        time.sleep(0.1)
    return ciphertext

def aes_ctr_decrypt(ciphertext, key, nonce):
    return aes_ctr_encrypt(ciphertext, key, nonce)

def process_encryption_decryption():
    global global_key, global_iv, global_ciphertext
    plaintext = text_area.get("1.0", "end-1c").strip()
    key_input = key_area.get("1.0", "end-1c").strip()
    iv_input = iv_area.get("1.0", "end-1c").strip()

    if key_input == "Enter your key here..." or plaintext == "Enter your text here..." or iv_input == "Enter your IV here...":
        text_area2.configure(state="normal")
        text_area2.delete("1.0", "end")
        text_area2.insert("1.0", "Please enter a valid message, key, and IV!")
        text_area2.configure(state="disabled")
        return

    try:
        # Convert key from hex to bytes
        key = binascii.unhexlify(key_input)
        if len(key) not in [16, 24, 32]:  # Check key size
            raise ValueError("Invalid key size. Key must be 128 (32 Hex), 192 (48 Hex), or 256 bits (64 Hex).")

        # Convert IV from hex to bytes
        iv = binascii.unhexlify(iv_input)
        if len(iv) != 8:  # Check IV size
            raise ValueError("Invalid IV size. IV must be 8 bytes (16 Hex).")

    except (binascii.Error, ValueError) as e:
        text_area2.configure(state="normal")
        text_area2.delete("1.0", "end")
        text_area2.insert("1.0", f"Error: {str(e)}")
        text_area2.configure(state="disabled")
        return

    mode = selected_option.get()

    # Measure encryption/decryption time
    start_time = time.time()

    if mode == "0":  # Encryption
        ciphertext = aes_ctr_encrypt(plaintext.encode(), key, iv)
        result = binascii.hexlify(ciphertext).decode()  # Convert ciphertext to hex
        global_key = key_input  # Store the key
        global_iv = iv_input    # Store the IV
        global_ciphertext = result  # Store the ciphertext

    else:  # Decryption
        try:
            # Convert ciphertext from hex to bytes
            ciphertext_bytes = binascii.unhexlify(plaintext)
            # Use the IV as the nonce
            nonce = binascii.unhexlify(iv_input)
            # Decrypt the ciphertext
            decrypted_bytes = aes_ctr_decrypt(ciphertext_bytes, key, nonce)
            try:
                result = decrypted_bytes.decode()  # Convert to text
            except UnicodeDecodeError:
                result = "Decryption failed! Output is not valid text."
        except (binascii.Error, ValueError) as e:
            result = f"Decryption failed! {str(e)}"

    end_time = time.time()
    elapsed_time = end_time - start_time  # Calculate elapsed time

    # Update output text area
    text_area2.configure(state="normal")
    text_area2.delete("1.0", "end")
    text_area2.insert("1.0", result)
    text_area2.configure(state="disabled")

    # Calculate and display statistics
    stats = f"""Encryption Statistics:
- Key Size: {len(key) * 8} bits
- IV Size: {len(iv) * 8} bits
- Ciphertext Length: {len(result) // 2} bytes (Hex)
- Time Taken: {elapsed_time:.4f} seconds
"""
    stats_area.configure(state="normal")
    stats_area.delete("1.0", "end")
    stats_area.insert("1.0", stats)
    stats_area.configure(state="disabled")

def measure_encryption_time():
    key_input = key_area.get("1.0", "end-1c").strip()

    if key_input == "Enter your key here...":
        text_area2.configure(state="normal")
        text_area2.delete("1.0", "end")
        text_area2.insert("1.0", "Please enter a valid key!")
        text_area2.configure(state="disabled")
        return

    try:
        key = binascii.unhexlify(key_input)
        if len(key) not in [16, 24, 32]:  # Check if the key is 128, 192, or 256 bits
            raise ValueError("Invalid key size. Key must be 128 (32 Hex), 192 (48 Hex), or 256 bits (64 Hex).")
    except (binascii.Error, ValueError) as e:
        text_area2.configure(state="normal")
        text_area2.delete("1.0", "end")
        text_area2.insert("1.0", f"Error: {str(e)}")
        text_area2.configure(state="disabled")
        return

    lengths = [10, 50, 100, 200, 500, 1000, 2000]
    key_labels = [f"AES-{len(key)*8}"]
    colors = ["#4B0082"]  #dark purple

    plt.figure(figsize=(7, 5), dpi=100)

    nonce = os.urandom(8)
    times = []

    for length in lengths:
        plaintext = os.urandom(length)
        start_time = time.time()
        aes_ctr_encrypt(plaintext, key, nonce)
        end_time = time.time()
        times.append(end_time - start_time)

    # Plot the curve for the provided key size
    plt.plot(lengths, times, marker='o', linestyle='-', color=colors[0], linewidth=2, markersize=6, label=key_labels[0])

    # Customizing the graph
    plt.xlabel("Text Length (bytes)", fontsize=12)
    plt.ylabel("Encryption Time (seconds)", fontsize=12)
    plt.title(f"AES-{len(key)*8} CTR Encryption Time", fontsize=14)
    plt.legend()  # Show legend
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.show()

def send_ip_window(key, iv, ciphertext):
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    ip_window = ctk.CTk()
    ip_window.geometry("400x150+500+300")
    ip_window.title('CryptXplorer')
    ip_window.resizable(False, False)

    # IP Address Entry Section
    ip_entry = ctk.CTkEntry(ip_window, placeholder_text="Enter the IP address", width=300)
    ip_entry.place(x=50, y=40)

    # Function to handle sending data over socket
    def send_data():
        ip_address = ip_entry.get().strip()
        if not ip_address:
            messagebox.showerror("Error", "Please enter a valid IP address.", parent=ip_window)
            return

        # Check if key, iv, and ciphertext are provided
        if not key or not iv or not ciphertext:
            messagebox.showerror("Error", "Key, IV, or encrypted text missing. Please ensure everything is generated correctly.", parent=ip_window)
            return

        try:
            static_key = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
            static_IV = bytes([0, 0, 0, 0, 0, 0, 0, 0])

            data = f"Key:{key}\nIV:{iv}\nCiphertext:{ciphertext}"
            encrypted_data = aes_ctr_encrypt(data.encode('utf-8'), static_key, static_IV)

            port = 12345  # Server's port
            # Send data using socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.settimeout(5)  # Set a timeout for the operation
        
        # Send to broadcast address (192.168.1.255) or specific IP
                s.sendto(encrypted_data, (ip_address, port))  # Send the encoded data
            messagebox.showinfo("Success", "Data sent successfully.", parent=ip_window)
            ip_window.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to send data: {e}", parent=ip_window)

    # Send button with improved styling
    send_button = ctk.CTkButton(ip_window, text="Send", command=send_data, corner_radius=20, width=100, height=30)
    send_button.place(x=150, y=100)

    # Run the window loop
    ip_window.mainloop()

def show_received_data(key, iv, cipher, sender_ip, sender_port):
    # Create a new top-level window
    receive_window = ctk.CTkToplevel(app)
    receive_window.title("Received Data")
    receive_window.geometry("400x400+400+150")  # Adjusted height to accommodate sender info

    # Add labels and text areas to display the received data
    ctk.CTkLabel(receive_window, text="Sender Info:", font=("Arial", 14)).place(x=10, y=10)
    sender_info = ctk.CTkTextbox(receive_window, wrap="word", font=("Arial", 12), fg_color="#2e2e2e", text_color="white", height=30, width=380)
    sender_info.insert("1.0", f"IP: {sender_ip}, Port: {sender_port}")
    sender_info.configure(state="disabled")  # Make it read-only
    sender_info.place(x=10, y=40)

    ctk.CTkLabel(receive_window, text="Key:", font=("Arial", 14)).place(x=10, y=80)
    key_display = ctk.CTkTextbox(receive_window, wrap="word", font=("Arial", 12), fg_color="#2e2e2e", text_color="white", height=50, width=380)
    key_display.insert("1.0", key)
    key_display.configure(state="disabled")  # Make it read-only
    key_display.place(x=10, y=110)

    ctk.CTkLabel(receive_window, text="IV:", font=("Arial", 14)).place(x=10, y=170)
    iv_display = ctk.CTkTextbox(receive_window, wrap="word", font=("Arial", 12), fg_color="#2e2e2e", text_color="white", height=50, width=380)
    iv_display.insert("1.0", iv)
    iv_display.configure(state="disabled")  # Make it read-only
    iv_display.place(x=10, y=200)

    ctk.CTkLabel(receive_window, text="Ciphertext:", font=("Arial", 14)).place(x=10, y=260)
    cipher_display = ctk.CTkTextbox(receive_window, wrap="word", font=("Arial", 12), fg_color="#2e2e2e", text_color="white", height=50, width=380)
    cipher_display.insert("1.0", cipher)
    cipher_display.configure(state="disabled")  # Make it read-only
    cipher_display.place(x=10, y=290)

    # Function to confirm and insert data into the main application
    def confirm_data():
        key_area.delete("1.0", "end")
        key_area.insert("1.0", key)
        iv_area.delete("1.0", "end")
        iv_area.insert("1.0", iv)
        text_area.configure(state="normal")
        text_area.delete("1.0", "end")
        text_area.insert("1.0", cipher)
        text_area.configure(state="disabled")

        receive_window.destroy()  # Close the receive window

    # Add Confirm and Discard buttons
    confirm_btn = ctk.CTkButton(receive_window, text="Confirm", corner_radius=20, fg_color="dark green", command=confirm_data)
    confirm_btn.place(x=40, y=350)

    discard_btn = ctk.CTkButton(receive_window, text="Discard", corner_radius=20, fg_color="red4", command=receive_window.destroy)
    discard_btn.place(x=210, y=350)

# Receive function
def receive():
    host = '0.0.0.0'  # Listen on all interfaces
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        server_socket.bind((host, port))
        print(f"Server listening on {host}:{port}...")

        with True:

            data, addr = server_socket.recvfrom(1024)  # Buffer size

            if data:
                static_key = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                static_IV = bytes([0, 0, 0, 0, 0, 0, 0, 0])
                received_text = aes_ctr_decrypt(data, static_key, static_IV)

                received_text = received_text.decode('utf-8').strip()  # Remove unnecessary spaces and \n
                print(f"Raw received data:\n{received_text}")

                # Extract Key, IV, and Ciphertext values
                key, iv, cipher = None, None, None
                for line in received_text.split('\n'):
                    if line.startswith("Key:"):
                        key = line.split("Key:")[1].strip()
                    elif line.startswith("IV:"):
                        iv = line.split("IV:")[1].strip()
                    elif line.startswith("Ciphertext:"):
                        cipher = line.split("Ciphertext:")[1].strip()

                # Show the received data in a separate window
                if key and iv and cipher:
                    sender_ip, sender_port = addr  # Extract sender IP and port
                    app.after(0, show_received_data, key, iv, cipher, sender_ip, sender_port)  # Use `after` to safely update the GUI
                else:
                    print("Error: Missing key, IV, or ciphertext.")

def start_receive_thread():
    threading.Thread(target=receive, daemon=True).start()

def start_measure_thread():
    threading.Thread(target=measure_encryption_time, daemon=True).start()

# GUI Components
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

app = ctk.CTk()
app.geometry("600x550+400+150")
app.title('CryptXplorer')
app.resizable(False, False)

logo_label = ctk.CTkLabel(master=app, text="AES-CTR", font=("Arial", 30))
logo_label.place(x=230, y=15)

frame = ctk.CTkFrame(app)
frame.place(x=10, y=60)
text_area = ctk.CTkTextbox(frame, wrap="word", font=("Arial", 12), fg_color="#2e2e2e", text_color="gray", height=50, width=550)
text_area.insert("1.0", "Enter your text here...")
text_area.bind("<FocusIn>", remove_placeholder)
text_area.bind("<FocusOut>", add_placeholder)
text_area.grid(row=0, column=0, padx=5, pady=5)

selected_option = ctk.StringVar(value="0")
radio1 = ctk.CTkRadioButton(app, text="Encryption", variable=selected_option, value="0")
radio1.place(x=150, y=250)
radio2 = ctk.CTkRadioButton(app, text="Decryption", variable=selected_option, value="1")
radio2.place(x=300, y=250)

frame3 = ctk.CTkFrame(app)
frame3.place(x=100, y=150)
key_area = ctk.CTkTextbox(frame3, wrap="word", font=("Arial", 12), fg_color="#2e2e2e", text_color="gray", height=20, width=350)
key_area.insert("1.0", "Enter your key here...")
key_area.bind("<FocusIn>", remove_placeholder)
key_area.bind("<FocusOut>", add_placeholder)
key_area.grid(row=0, column=0, padx=5, pady=5)

frame4 = ctk.CTkFrame(app)
frame4.place(x=100, y=200)
iv_area = ctk.CTkTextbox(frame4, wrap="word", font=("Arial", 12), fg_color="#2e2e2e", text_color="gray", height=20, width=350)
iv_area.insert("1.0", "Enter your iv here...")
iv_area.bind("<FocusIn>", remove_placeholder)
iv_area.bind("<FocusOut>", add_placeholder)
iv_area.grid(row=0, column=0, padx=5, pady=5)

frame2 = ctk.CTkFrame(app)
frame2.place(x=10, y=290)
text_area2 = ctk.CTkTextbox(frame2, wrap="word", font=("Arial", 12), fg_color="#2e2e2e", text_color="white", height=50, width=550)
text_area2.grid(row=0, column=0, padx=5, pady=5)
text_area2.configure(state="disabled")

frame_stats = ctk.CTkFrame(app)
frame_stats.place(x=10, y=360)
stats_area = ctk.CTkTextbox(frame_stats, wrap="word", font=("Arial", 12), fg_color="#2e2e2e", text_color="white", height=85, width=550)
stats_area.grid(row=0, column=0, padx=5, pady=5)
stats_area.configure(state="disabled")

reset_btn = ctk.CTkButton(master=app, width=100, text="Reset", corner_radius=20, fg_color="red4", command=lambda: reset())
reset_btn.place(x=10, y=470)
submit_btn = ctk.CTkButton(master=app, width=100, text="Submit", corner_radius=20, fg_color="dark green", command=process_encryption_decryption)
submit_btn.place(x=120, y=470)
statistic_btn = ctk.CTkButton(master=app, width=100, text="Statistic", corner_radius=20, fg_color="darkBlue", command=lambda: start_measure_thread())
statistic_btn.place(x=230, y=470)
send_btn = ctk.CTkButton(master=app, width=100, text="Send", corner_radius=20, fg_color="purple4", command=lambda: send_ip_window(global_key, global_iv, global_ciphertext))
send_btn.place(x=340, y=470)
receive_btn = ctk.CTkButton(master=app, width=100, text="Receive", corner_radius=20, fg_color="purple2", command=start_receive_thread)
receive_btn.place(x=450, y=470)

app.mainloop()