import getpass, json
from config import VAULT_FILE

# opens and decrypts Vault File.
def load_vault(fernet):
    
    try:
        with open(VAULT_FILE, 'rb') as f:
            encrypted = f.read()
        decrypted  = fernet.decrypt(encrypted)
        vault = json.loads(decrypted.decode("utf-8"))
        return vault
            
    except FileNotFoundError:
        print("Vault file not found.")
        pause()
        return None        

    except Exception as e:
        print(f"Unexpected error: {e}")
        pause()
        return None 
   
# Encrypts and closes Vault File.
def save_vault(vault, fernet): 

    vault_json = json.dumps(vault).encode("utf-8")
    encrypted = fernet.encrypt(vault_json)

    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

# Creates New Groups 
def add_group(vault, fernet):


    group_name = input("Enter new group name: ").strip().lower()

    if group_name in vault["groups"]:
        print("Category already exists.")
        pause()
        return
    else:
        vault ["groups"][group_name] = {}
        save_vault(vault, fernet)
    
    print("Group successfully created.")
    pause()



def view_groups(vault):
    print("\n----VAULT VIEWING----")

    if not vault["groups"]:
        print("No categories yet.")
        pause()
        return
    
    print("\nType the name of the category you would like to see")
    print("\nType 'List' to see all the categories in the vault")
    print("\nType 'Exit' if you want to return to the main menu")

    while True:
        choice = input("\nWhich category would you like to enter? ").strip().lower()

        if choice == "exit":
            print("Returning to menu. ")
            pause()
            break
        
        elif choice == "list":
            print("\nSTORED CATEGORIES:")
            for key in vault["groups"]:
                print(f"- {key}")
            print()
            continue

        elif choice in vault["groups"]:
            view_category(vault, choice)           

        else:
            print("\nCategory not found. Try Again\n")

def view_category(vault, category):
    entries = vault["groups"][category]

    #shows masked credentials
    for site, creds in sorted(entries.items()):
        print(f"\nSite: {site}")
        print(f"User: {creds['username']}")
        print(f"Password: {'*' * len(creds['password'])}")
    print()

    #reveals specific credential
    reveal = input("Enter the site name to reveal the password (or press Enter to skip): ").strip().lower()

    if reveal in entries:
        reveal_pass(entries[reveal])
    elif reveal:
        print("Credential not found.")
    
                

def add_credential(vault, fernet):
    print("Available Groups:") 
    for g in vault["groups"]: 
        print("-", g)

   
    group = input("Enter Category Name\n").strip().lower()

    while group not in vault["groups"]:
        print("Group does not exist.")
        group = input("Enter Category Name\n").strip().lower() 
        
        
    site = input("Site/Application: ").strip().lower()
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    vault["groups"][group][site] = {
        "username": username,
        "password": password
    }


    save_vault(vault, fernet)

    print("Credential added successfully.")
    pause()

def delete_credential(vault, fernet):

    if not vault["groups"]:
        print("No categories available.")
        pause()
        return

    print("\nAvailable Categories:")
    for g in vault["groups"]:
        print(f"- {g}")
        
    group = input("Enter Category Name: ").strip().lower()
    

    if group not in vault["groups"]:
        print("Group does not exist.")
        pause()
        return
    
    entries = vault["groups"][group]

    if not entries:
        print("No credentials stored in this group.")
        pause()
        return
    

   #List stored credentials 
    print("\nStored Credentials:")

    site_list = list(entries.keys())

    for i, site in enumerate(site_list, start=1):
        print(f"{i}. {site} ({entries[site]['username']})")

    try:
        choice = int(input("Select credential number: ")) - 1

        if choice < 0 or choice >= len(site_list):
            print("Invalid selection.")
            pause()
            return

        site = site_list[choice]
        entry = entries[site]

        # CONFIRMATION STEP (new part)
        print(f"\nYou selected:")
        print(f"Site: {site}")
        print(f"Username: {entry['username']}")

        confirm = input("Are you sure you want to delete this credential? (y/n): ").strip().lower()

        if confirm != "y":
            print("Deletion cancelled.")
            pause()
            return

        deleted = entries.pop(site)
        save_vault(vault, fernet)
        print(f"Credential for {site} deleted.")
        pause()

    except (ValueError, IndexError):
        print("Invalid selection.")
        pause()

    
    # 
def reveal_pass(entry):
    reveal = input("Reveal password? (y/n): ").strip().lower()

    if reveal == "y":
        print(f"Password: {entry['password']}")


def pause():
    input("\nPress Enter to continue...")