import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip
import re

class AdvancedPasswordGenerator:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Password Generator")
        master.geometry("550x700")
        master.resizable(False, False)

        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Define color scheme
        self.bg_color = "seashell"
        self.fg_color = "black"
        self.accent_color = "lightgreen"
        self.button_color = "skyblue"

        # Configure styles
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("TLabel", background=self.bg_color, foreground=self.fg_color, font=("Helvetica", 10))
        self.style.configure("TCheckbutton", background=self.bg_color, foreground=self.fg_color, font=("Helvetica", 10))
        self.style.configure("TButton", background=self.button_color, foreground=self.fg_color, font=("Helvetica", 10, "bold"))
        self.style.map("TButton", background=[('active', self.accent_color)])

        self.master.configure(bg=self.bg_color)

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.master, padding="20 20 20 20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Title
        title_label = ttk.Label(main_frame, text="Advanced Password Generator", font=("Helvetica", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # Password Length
        ttk.Label(main_frame, text="Password Length:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.length_var = tk.StringVar(value="12")
        length_entry = ttk.Entry(main_frame, textvariable=self.length_var, width=5)
        length_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        # Complexity Options
        complexity_frame = ttk.LabelFrame(main_frame, text="Character Types", padding="10 10 10 10")
        complexity_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="we")

        self.lowercase_var = tk.BooleanVar(value=True)
        self.uppercase_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(complexity_frame, text="Lowercase (a-z)", variable=self.lowercase_var).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(complexity_frame, text="Uppercase (A-Z)", variable=self.uppercase_var).grid(row=0, column=1, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(complexity_frame, text="Digits (0-9)", variable=self.digits_var).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(complexity_frame, text="Symbols (!@#$%^&*)", variable=self.symbols_var).grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Security Rules
        security_frame = ttk.LabelFrame(main_frame, text="Security Rules", padding="10 10 10 10")
        security_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="we")

        self.no_similar_var = tk.BooleanVar(value=False)
        self.no_ambiguous_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(security_frame, text="No Similar Characters (i, l, 1, L, o, 0, O)", variable=self.no_similar_var).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(security_frame, text="No Ambiguous Characters ({}[]()/\'\")`~,;:.<>)", variable=self.no_ambiguous_var).grid(row=1, column=0, padx=5, pady=5, sticky="w")

        # Customization
        custom_frame = ttk.LabelFrame(main_frame, text="Customization", padding="10 10 10 10")
        custom_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="we")

        ttk.Label(custom_frame, text="Exclude Characters:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.exclude_chars = tk.StringVar()
        ttk.Entry(custom_frame, textvariable=self.exclude_chars, width=30).grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Generate Button
        generate_button = ttk.Button(main_frame, text="Generate Password", command=self.generate_password)
        generate_button.grid(row=5, column=0, columnspan=2, pady=20)

        # Password Display
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=self.password_var, width=40, font=("Helvetica", 12), state="readonly")
        password_entry.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

        # Copy Button
        copy_button = ttk.Button(main_frame, text="Copy to Clipboard", command=self.copy_to_clipboard)
        copy_button.grid(row=7, column=0, columnspan=2, pady=10)

        # Password Strength Meter
        self.strength_var = tk.StringVar(value="Password Strength: N/A")
        strength_label = ttk.Label(main_frame, textvariable=self.strength_var, font=("Helvetica", 10, "bold"))
        strength_label.grid(row=8, column=0, columnspan=2, pady=10)

    def generate_password(self):
        # Input Validation
        try:
            length = int(self.length_var.get())
            if length <= 0:
                raise ValueError("Password length must be greater than 0")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return

        # Character Set Handling
        char_sets = []
        if self.lowercase_var.get():
            char_sets.append(string.ascii_lowercase)
        if self.uppercase_var.get():
            char_sets.append(string.ascii_uppercase)
        if self.digits_var.get():
            char_sets.append(string.digits)
        if self.symbols_var.get():
            char_sets.append(string.punctuation)

        if not char_sets:
            messagebox.showerror("Error", "Please select at least one character set")
            return

        all_chars = ''.join(char_sets)

        # Security Rules
        if self.no_similar_var.get():
            all_chars = ''.join(c for c in all_chars if c not in 'il1Lo0O')
        if self.no_ambiguous_var.get():
            all_chars = ''.join(c for c in all_chars if c not in '{}[]()/\'"`~,;:.<>')

        # Customization
        exclude_chars = self.exclude_chars.get()
        all_chars = ''.join(c for c in all_chars if c not in exclude_chars)

        if not all_chars:
            messagebox.showerror("Error", "No characters available with current settings")
            return

        # Password Generation
        password = ''.join(random.choice(all_chars) for _ in range(length))

        # Ensure at least one character from each selected set is included
        for char_set in char_sets:
            if not any(c in char_set for c in password):
                replace_index = random.randint(0, length - 1)
                password = password[:replace_index] + random.choice(char_set) + password[replace_index + 1:]

        self.password_var.set(password)
        self.update_strength_meter(password)

    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard")
        else:
            messagebox.showerror("Error", "Password not generated yet")

    def update_strength_meter(self, password):
        strength = self.calculate_password_strength(password)
        if strength < 3:
            strength_text = "Weak"
            color = "#E74C3C"  # Red
        elif strength < 4:
            strength_text = "Medium"
            color = "#F39C12"  # Orange
        elif strength < 5:
            strength_text = "Strong"
            color = "#2ECC71"  # Green
        else:
            strength_text = "Very Strong"
            color = "#27AE60"  # Dark Green

        self.strength_var.set(f"Password Strength: {strength_text}")
        self.style.configure("Strength.TLabel", foreground=color)

    def calculate_password_strength(self, password):
        strength = 0
        if len(password) >= 8:
            strength += 1
        if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
            strength += 1
        if re.search(r"\d", password):
            strength += 1
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            strength += 1
        if len(password) >= 12:
            strength += 1
        return strength

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedPasswordGenerator(root)
    root.mainloop()



