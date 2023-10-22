import hashlib
import time
import os
#from plyer import notification

# Define a dictionary to store the hashes of trusted files
trusted_files = {
    '/bin/bash': '1e07062aebac35b8f0012a04fda2a7f5',
    '/bin/ls': '7987cf330ff5bb94015dfbb9eae5a99f',
    '/home/kali/Documents/Projects/example': '894dddf3304cbcb0fe04f7c2bbd56073',
    # Add more trusted files and their corresponding hashes here
}

RED = '\033[91m'
GREEN = '\033[92m'
RESET = '\033[0m'

def calculate_file_hash(file_path):
    """Calculate the MD5 hash of a file."""
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def check_integrity():
    modified_files = []	
    """Check the integrity of system files."""
    for file_path, expected_hash in trusted_files.items():
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            continue

        actual_hash = calculate_file_hash(file_path)
        if actual_hash == expected_hash:
            print(f"{GREEN}File {file_path} is intact.{RESET}")
        else:
            print(f"{RED}File {file_path} has been modified! Previous hash: {expected_hash}, Actual hash: {actual_hash}{RESET}")
            modified_files.append(file_path)
            
            
    if modified_files:
        # Si des fichiers ont été modifiés, envoyer la notification avec la liste des fichiers
        notification_title = "File Modification Detected"
        notification_text = "The following files have been modified:\n"
        notification_text += "\n".join(modified_files)
        notification.notify(
            title=notification_title,
            message=notification_text,
            app_name="Integrity Checker"
        )

if __name__ == "__main__":
    while True:
        check_integrity()
        time.sleep(15)

