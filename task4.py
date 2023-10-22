import tkinter as tk
from tkinter import filedialog
import hashlib

def afficher_hashes():
    algo = algo_var.get()
    fichier = fichier_entry.get()

    try:
        with open(fichier, 'r', encoding='latin-1') as f:
            hashes = []

            for mot in f.read().split():
                mot = mot.strip()
                if algo == "MD5":
                    mot_hash = hashlib.md5(mot.encode()).hexdigest()
                elif algo == "SHA256":
                    mot_hash = hashlib.sha256(mot.encode()).hexdigest()
                hashes.append(f"{mot}: {mot_hash}")

            result_text.config(state=tk.NORMAL)  # Enable text widget for editing
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, '\n'.join(hashes))
            result_text.config(state=tk.DISABLED)  # Disable text widget for viewing
    except FileNotFoundError:
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Fichier introuvable.")
        result_text.config(state=tk.DISABLED)
    except Exception as e:
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Erreur: {str(e)}")
        result_text.config(state=tk.DISABLED)

def verifier_hash():
    algo = algo_var.get()
    hash_to_check = hash_to_check_entry.get()
    fichier = fichier_entry.get()

    if not fichier:
        result_label.config(text="Veuillez sélectionner un fichier.")
        return

    try:
        with open(fichier, 'r', encoding='latin-1') as f:
            for mot in f.read().split():
                mot = mot.strip()
                if algo == "MD5":
                    mot_hash = hashlib.md5(mot.encode()).hexdigest()
                elif algo == "SHA256":
                    mot_hash = hashlib.sha256(mot.encode()).hexdigest()
                if mot_hash == hash_to_check:
                    result_label.config(text=f"Le mot correspondant est: {mot}", fg="green")
                    return
            result_label.config(text="Aucun mot correspondant trouvé.")
    except Exception as e:
        result_label.config(text=f"Erreur: {str(e)}")

def browse_file():
    filename = filedialog.askopenfilename()
    if filename:
        fichier_entry.delete(0, tk.END)
        fichier_entry.insert(0, filename)

window = tk.Tk()
window.title("Affichage et Vérification de Hashes")
window.geometry("700x700")

algo_var = tk.StringVar()
algo_label = tk.Label(window, text="Sélectionnez l'algorithme:")
algo_label.pack()
algo_options = ["MD5", "SHA256"]
algo_menu = tk.OptionMenu(window, algo_var, *algo_options)
algo_menu.pack()

fichier_label = tk.Label(window, text="Sélectionnez le fichier contenant les mots:")
fichier_label.pack()
fichier_entry = tk.Entry(window)
fichier_entry.pack()
fichier_button = tk.Button(window, text="Parcourir", command=browse_file)
fichier_button.pack()

hash_to_check_label = tk.Label(window, text="Entrez le hash à vérifier:")
hash_to_check_label.pack()
hash_to_check_entry = tk.Entry(window)
hash_to_check_entry.pack()

afficher_button = tk.Button(window, text="Afficher Hashes", command=afficher_hashes)
afficher_button.pack()

verifier_button = tk.Button(window, text="Vérifier Hash", command=verifier_hash)
verifier_button.pack()

result_text = tk.Text(window, height=15, width=40, state=tk.DISABLED)
result_text.pack()

result_label = tk.Label(window, text="")
result_label.pack()

window.mainloop()
