import tkinter as tk
from tkinter import messagebox
import re

def check_password_strength(password):
    # Check the length of the password
    length_score = len(password) // 4  # Assign a score based on the length

    # Check for uppercase and lowercase characters
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    case_score = (has_upper + has_lower) * 2  # Assign a score for cases

    # Check for digits and special characters
    has_digit = any(c.isdigit() for c in password)
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    char_score = (has_digit + has_special) * 3  # Assign a score for characters

    # Combine scores to determine strength
    total_score = length_score + case_score + char_score

    if total_score >= 10:
        return "Strong"
    elif total_score >= 6:
        return "Moderate"
    else:
        return "Weak"

def evaluate_password():
    password = password_entry.get()
    strength = check_password_strength(password)
    messagebox.showinfo("Password Strength", f"Password strength: {strength}")

# Create the main window
window = tk.Tk()
window.title("Password Strength Checker")

# Create and place widgets
label = tk.Label(window, text="Enter a password:")
label.pack()

password_entry = tk.Entry(window, show="*")
password_entry.pack()

evaluate_button = tk.Button(window, text="Evaluate", command=evaluate_password)
evaluate_button.pack()

# Start the main loop
window.mainloop()
