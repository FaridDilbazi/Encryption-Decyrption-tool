import base64
import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from PIL import Image, ImageTk

class EnhancedEncryptionTool:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Security Tool")
        self.window.geometry("800x600")
        self.window.configure(bg='#f0f0f0')
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', padding=6, relief="flat", background="#2196F3")
        style.configure('TRadiobutton', background='#f0f0f0')
        style.configure('TFrame', background='#f0f0f0')
        
        main_frame = ttk.Frame(self.window)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        self.methods = {
            "Base64": self.base64_operation,
            "SHA-256": self.sha256_operation,
            "MD5": self.md5_operation,
            "Fernet (Symmetric)": self.fernet_operation,
            "Caesar Cipher": self.caesar_cipher_operation,
            "ROT13": self.rot13_operation,
            "Binary": self.binary_operation
        }
        
        left_panel = ttk.Frame(main_frame)
        left_panel.pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        ttk.Label(left_panel, text="Encryption Method:", font=('Arial', 10, 'bold')).pack(pady=5)
        self.method_var = tk.StringVar(value="Base64")
        for method in self.methods.keys():
            ttk.Radiobutton(left_panel, text=method, variable=self.method_var, 
                           value=method, command=self.update_options).pack(pady=2)
        
        ttk.Label(left_panel, text="\nOperation:", font=('Arial', 10, 'bold')).pack(pady=5)
        self.operation_var = tk.StringVar(value="encrypt")
        ttk.Radiobutton(left_panel, text="Encrypt", variable=self.operation_var, 
                       value="encrypt").pack()
        ttk.Radiobutton(left_panel, text="Decrypt", variable=self.operation_var, 
                       value="decrypt").pack()
        
        self.options_frame = ttk.LabelFrame(left_panel, text="Parameters", padding=10)
        self.options_frame.pack(pady=10, fill=tk.X)
        
        self.shift_var = tk.StringVar(value="3")
        self.shift_frame = ttk.Frame(self.options_frame)
        ttk.Label(self.shift_frame, text="Sliding:").pack(side=tk.LEFT)
        ttk.Entry(self.shift_frame, textvariable=self.shift_var, width=5).pack(side=tk.LEFT, padx=5)
        
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, padx=10, fill=tk.BOTH, expand=True)
        
        ttk.Label(right_panel, text="Login Information:", font=('Arial', 10, 'bold')).pack(pady=5)
        self.input_preview = scrolledtext.ScrolledText(right_panel, height=8, width=50)
        self.input_preview.pack(pady=5, fill=tk.X)
        
        ttk.Label(right_panel, text="Result:", font=('Arial', 10, 'bold')).pack(pady=5)
        self.output_preview = scrolledtext.ScrolledText(right_panel, height=8, width=50)
        self.output_preview.pack(pady=5, fill=tk.X)
        
        button_frame = ttk.Frame(right_panel)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Select File", command=self.select_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Enter Text", command=self.enter_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Edit", command=self.process_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save the result", command=self.save_result).pack(side=tk.LEFT, padx=5)
        
        self.selected_file = None
        self.fernet_key = None
        self.result = None
        
        self.update_options()
        
    def update_options(self):
        for widget in self.options_frame.winfo_children():
            widget.pack_forget()
            
        method = self.method_var.get()
        if method == "Caesar Cipher":
            self.shift_frame.pack()
            
    def enter_text(self):
        dialog = tk.Toplevel(self.window)
        dialog.title("Enter Text")
        dialog.geometry("400x300")
        
        text_area = scrolledtext.ScrolledText(dialog, height=10, width=40)
        text_area.pack(padx=10, pady=10)
        
        def confirm():
            text = text_area.get("1.0", tk.END).strip()
            self.input_preview.delete("1.0", tk.END)
            self.input_preview.insert(tk.END, text)
            dialog.destroy()
            
        ttk.Button(dialog, text="Confirm", command=confirm).pack(pady=5)
        
    def select_file(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            with open(self.selected_file, 'rb') as file:
                data = file.read()
                try:
                
                    preview = data.decode('utf-8')
                except:
                    preview = f"Binary file: {os.path.basename(self.selected_file)}"
                    
            self.input_preview.delete("1.0", tk.END)
            self.input_preview.insert(tk.END, preview)
            
    def base64_operation(self, data, operation):
        if operation == "encrypt":
            return base64.b64encode(data).decode()
        else:
            return base64.b64decode(data)
            
    def sha256_operation(self, data, operation):
        if operation == "encrypt":
            return hashlib.sha256(data).hexdigest()
        return "SHA-256 is a one-way hash function, it cannot be deciphered!"

    def md5_operation(self, data, operation):
        if operation == "encrypt":
            return hashlib.md5(data).hexdigest()
        return "MD5 is a one-way hash function, it cannot be deciphered!"

    def fernet_operation(self, data, operation):
        if not self.fernet_key:
            self.fernet_key = Fernet.generate_key()
        f = Fernet(self.fernet_key)
        
        if operation == "encrypt":
            return f.encrypt(data)
        else:
            return f.decrypt(data)

    def caesar_cipher_operation(self, data, operation):
        shift = int(self.shift_var.get())
        result = bytearray()
        for byte in data:
            if operation == "encrypt":
                result.append((byte + shift) % 256)
            else:
                result.append((byte - shift) % 256)
        return result

    def rot13_operation(self, data, operation):
        result = bytearray()
        for byte in data:
            if byte >= ord('A') and byte <= ord('Z'):
                result.append(((byte - ord('A') + 13) % 26) + ord('A'))
            elif byte >= ord('a') and byte <= ord('z'):
                result.append(((byte - ord('a') + 13) % 26) + ord('a'))
            else:
                result.append(byte)
        return result

    def binary_operation(self, data, operation):
        if operation == "encrypt":
            return ' '.join(format(byte, '08b') for byte in data)
        else:
            binary_list = data.split()
            return bytes(int(binary, 2) for binary in binary_list)

    def process_data(self):
        try:
            if self.selected_file:
                with open(self.selected_file, 'rb') as file:
                    data = file.read()
            else:
                data = self.input_preview.get("1.0", tk.END).strip().encode()
            
            method = self.method_var.get()
            operation = self.operation_var.get()
            
            self.result = self.methods[method](data, operation)
            
            self.output_preview.delete("1.0", tk.END)
            if isinstance(self.result, (str, bytes)):
                preview = self.result if isinstance(self.result, str) else self.result.decode('utf-8', errors='replace')
                self.output_preview.insert(tk.END, preview)
            else:
                self.output_preview.insert(tk.END, f"Binary data processed successfully")
                
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def save_result(self):
        if not self.result:
            messagebox.showerror("Error", "First, process the data!")
            return
            
        save_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if save_path:
            with open(save_path, 'wb') as file:
                if isinstance(self.result, str):
                    file.write(self.result.encode())
                else:
                    file.write(self.result)
            messagebox.showinfo("Successful", f"The result was saved: {save_path}")

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = EnhancedEncryptionTool()
    app.run()