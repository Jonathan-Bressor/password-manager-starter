
from getpass import getpass
from password_manager import add_credential, get_credential, list_sites

MENU = '''
=== Simple Password Manager ===
1. Add credential
2. Retrieve credential
3. List all sites
4. Exit
'''

def main():
    print("Welcome!")
    while True:
        print(MENU)
        choice = input("> ").strip()

        if choice == "1":
            master = getpass("Master password: ")
            site = input("Site name: ").strip()
            username = input("Username: ").strip()
            password = getpass("Password: ")
            add_credential(master, site, username, password)
        elif choice == "2":
            master = getpass("Master password: ")
            site = input("Site name: ").strip()
            get_credential(master, site)
        elif choice == "3":
            list_sites()
        elif choice == "4":
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
