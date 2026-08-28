import os, getpass, base64, json, hmac, time
from cryptography.fernet import Fernet
from auth.session import session
from vault.vault import load_vault, add_group, add_credential, delete_credential, view_groups, pause
from auth.auth import setup_master_password, login, verify_masterpass
from USB.usb_installer import register_install_usb, validate_usb, find_file_usb
from auth.manage_set import change_masterpass, generate_recovery_key, validate_recovery, change_usb_pin
from crypto.crypto_utils import derive_fernet_key
from config import MASTER_JSON, VAULT_FILE

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print(r"""
 ___.___________..______  ____     __     _______   ______   .  ______._____ ______..     ______       _______     _______. 
|           ||   _  \     |  | |   ____| /  __  \  |   _  \    |           ||   _  \     |   ____|   /       |    /       |
`---|  |----`|  |_)  |    |  | |  |__   |  |  |  | |  |_)  |   `---|  |----`|  |_)  |    |  |__     |   (----`   |   (----`
    |  |     |      /     |  | |   __|  |  |  |  | |      /        |  |     |      /     |   __|     \   \        \   \    
    |  |     |  |\  \----.|  | |  |     |  `--'  | |  |\  \----.   |  |     |  |\  \----.|  |____.----)   |   .----)   |   
    |__|     | _| `._____||__| |__|      \______/  | _| `._____|   |__|     | _| `._____||_______|_______/    |_______/    

                                            OPEN-SOURCE PASSWORD MANAGER!
    """)

def main_menu(vault, fernet):

    while True:
        clear_screen()
        print_banner()
        print("WELCOME TO THE VAULT")
        print("\nMAIN MENU")
        print("CHOOSE WHERE YOU WOULD LIKE TO NAVIGATE! PLEASE SELECT A NUMBER:")
        print("\n1. Manage Groups")
        print("2. View Credentials")
        print("3. Security Settings")
        print("4. Logout")

        choice = input("> ")
 
        if choice == "1":
            print("\nHow would you like to proceed?")
            print("1. Create New Group")
            print("2. Add Credential to a Group")
            print("3. Delete Credential from Group")

            choice2 = input("> ")

            if choice2 == "1":
                add_group(vault, fernet)
            elif choice2 == "2":
                add_credential(vault, fernet)
            elif choice2 == "3":
                delete_credential(vault, fernet)
            else:
                print("Invalid choice.")

        elif choice == "2":
            view_groups(vault)
        
        elif choice == "3":
            print("\nWhich setting would you like to change?")
            print("1. Change Master Password")
            print("2. Update Biometric Settings")

            choice3 = input("> ")

            if choice3 == "1":
                change_masterpass()
            elif choice3 == "2":
                validate_recovery()
                

        elif choice == "4":
            session.authenticated = False
            session.login_time = None
            session.auth_method = None
            vault.clear()
            break

        else:
            print("Invalid choice.")
            pause() 

def recovery_menu():

    print("You MUST have 2 of 3 authentication factors to recover account.")
    print("\nRECOVERY CHOICES: ")
    print("1. I Forgot my USB PIN")
    print("2. I Forgot my Master Password")
    print("3. I Lost my USB")
    print("")

    choice2 = input("> ")
    if choice2 == "1":
        if verify_masterpass():
            if validate_recovery():
                change_usb_pin()

    #elif choice2 == "2": 
      #  if     


if __name__ == "__main__":

    # First-time setup check
    if not (os.path.exists(MASTER_JSON) and os.path.exists(VAULT_FILE)):

        print("First-Time Setup Detected!")

        if not register_install_usb():
            print("Valid Installation USB not detected.")
            exit()

        print("Installation USB Registered Successfully!")
        setup_master_password()
        recovery_key = generate_recovery_key()

        if not recovery_key:
            print("Recovery Key Not Initialized")
            exit()     

    if not validate_usb():
        print("ACCESS DENIED!")
        exit()

    # ENTRANCE TO PASSWORD MANAGER
    print("=== PASSWORD MANAGER ===")
    print("\n1. Login")
    print("2. Account Recovery")
    print("3. Exit")

    choice = input("> ")

    if choice == "1":
        fernet = login()

        if not fernet:
            print("ACCESS DENIED!")
            exit()

        vault = load_vault(fernet)
        if vault is None:
            print("Failed to load vault.")
            exit()

        main_menu(vault, fernet)

    elif choice == "2":
        recovery_menu()

    elif choice == "3":
        exit()

