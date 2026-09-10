import os, base64
from cryptography.fernet import Fernet
from auth.session import session
from vault.vault import load_vault, add_group, add_credential, delete_credential, view_groups, pause
from auth.auth import setup_master_password, login
from auth.recovery import recover_masterpass, recover_lost_usb
from auth.manage_set import change_masterpass, change_usb_pin
from USB.usb_auth import find_file_usb
from config import MASTER_JSON, VAULT_FILE

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def display_recovery_key(recovery_key):
    clear_screen()

    print("=" * 60)
    print("                 RECOVERY KEY")
    print("=" * 60)
    print()
    print("  IMPORTANT: SAVE THIS KEY IN A SECURE LOCATION.")
    print()
    print(f"  {recovery_key}")
    print()
    print("  This key will NOT be shown again.")
    print("  Store it somewhere safe and accessible.")
    print()
    print("  Do not share this key with anyone.")
    print()
    print("=" * 60)
    print()
    
    while True:
        confirmation = input(
            'Type "SAVED" after you have securely recorded your recovery key: '
        ).strip()

        if confirmation == "SAVED":
            break

        print('Please type "SAVED" once you have securely recorded the key.')
    clear_screen()


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

def enter_vault(vault_key, usb_secret):
    session.start(vault_key, usb_secret)
    fernet = Fernet(base64.urlsafe_b64encode(vault_key))
    vault = load_vault(fernet)
    if vault is None:
        print("Failed to load vault.")
        return
    main_menu(vault, fernet)

def main_menu(vault, fernet):

    while True:
        if not session.is_valid():
            print("Session expired. Please log in again.")
            break
        session.touch()

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
            print("2. Change USB PIN")

            choice3 = input("> ")

            if choice3 == "1":
                changed = change_masterpass()

                if changed:
                    display_recovery_key(changed)

            elif choice3 == "2":
                changed = change_usb_pin()

                if changed:
                    display_recovery_key(changed)
            else:
                print("Invalid choice.")


        elif choice == "4":
            session.clear()
            vault.clear()
            print("Logged Out.")
            break

        else:
            print("Invalid choice.")
            pause() 

def recovery_menu():

    print("You MUST have 2 of 3 authentication factors to recover account.")
    print("\nRECOVERY CHOICES: ")
    print("1. I Forgot my PIN / Lost my USB")
    print("2. I Forgot my Master Password")
    print("")

    choice2 = input("> ")
    if choice2 == "1":
        result = recover_lost_usb()

    elif choice2 == "2": 
        result = recover_masterpass()

    else:
        print("Invalid choice.")
        return
        
    if not result:
        print("ACCESS DENIED!")
        return

    vault_key, usb_secret, recovery_key = result

    display_recovery_key(recovery_key)

    enter_vault(vault_key, usb_secret)

if __name__ == "__main__":

    # First-time setup check
    if not (os.path.exists(MASTER_JSON) and os.path.exists(VAULT_FILE)):

        print("First-Time Setup Detected!")

        usb_path, _ = find_file_usb()
        if not usb_path:
            print("Installation USB not detected.")
            exit()

        recovery_key = setup_master_password()

        if not recovery_key:
            print("Setup failed.")
            exit()

        display_recovery_key(recovery_key)



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

        enter_vault(session.vault_key, session.usb_secret)

    elif choice == "2":
        recovery_menu()

    elif choice == "3":
        exit()

