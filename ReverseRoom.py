import shutil
from colorama import Fore, Style, init
import subprocess
import time
import os
import re

init(autoreset=True)

logo = r"""
 ██▀███  ▓█████ ██▒   █▓▓█████  ██▀███    ██████ ▓█████  ██▀███   ▒█████   ▒█████   ███▄ ▄███▓
▓██ ▒ ██▒▓█   ▀▓██░   █▒▓█   ▀ ▓██ ▒ ██▒▒██    ▒ ▓█   ▀ ▓██ ▒ ██▒▒██▒  ██▒▒██▒  ██▒▓██▒▀█▀ ██▒
▓██ ░▄█ ▒▒███   ▓██  █▒░▒███   ▓██ ░▄█ ▒░ ▓██▄   ▒███   ▓██ ░▄█ ▒▒██░  ██▒▒██░  ██▒▓██    ▓██░
▒██▀▀█▄  ▒▓█  ▄  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄    ▒   ██▒▒▓█  ▄ ▒██▀▀█▄  ▒██   ██░▒██   ██░▒██    ▒██ 
░██▓ ▒██▒░▒████▒  ▒▀█░  ░▒████▒░██▓ ▒██▒▒██████▒▒░▒████▒░██▓ ▒██▒░ ████▓▒░░ ████▓▒░▒██▒   ░██▒
░ ▒▓ ░▒▓░░░ ▒░ ░  ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░   ░  ░
  ░▒ ░ ▒░ ░ ░  ░  ░ ░░   ░ ░  ░  ░▒ ░ ▒░░ ░▒  ░ ░ ░ ░  ░  ░▒ ░ ▒░  ░ ▒ ▒░   ░ ▒ ▒░ ░  ░      ░
  ░░   ░    ░       ░░     ░     ░░   ░ ░  ░  ░     ░     ░░   ░ ░ ░ ░ ▒  ░ ░ ░ ▒  ░      ░   
   ░        ░  ░     ░     ░  ░   ░           ░     ░  ░   ░         ░ ░      ░ ░         ░   
                    ░                                                                           
"""

def print_centered(text, color=Fore.WHITE, style=Style.NORMAL):
    cols = shutil.get_terminal_size().columns
    for line in text.splitlines():
        print(color + style + line.center(cols) + Style.RESET_ALL)

def print_header():
    print_centered(logo, Fore.RED, Style.BRIGHT)

    binary_text = "01010010 01100101 01110110 01100101 01110010 01110011 01100101 01010010 01101111 01101111 01101101\n\n"
    print_centered(binary_text, Fore.GREEN, Style.BRIGHT)

    time.sleep(0.5)
    info()

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def get_file_type(file_path):
    try:
        result = subprocess.run(
            ["file", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        output = result.stdout.lower()

        if "pe32" in output or "windows" in output:
            return "PE"
        elif "elf" in output:
            return "ELF"
        elif "mach-o" in output:
            return "Mach-O"
        else:
            return "Unknown"

    except:
        return "Unknown"
    
def show_status_bar(current_file):
    cols = shutil.get_terminal_size().columns

    if not current_file or not os.path.exists(current_file):
        status = Fore.RED + "No file selected"
    else:
        size = os.path.getsize(current_file)
        size_kb = round(size / 1024, 2)
        file_type = get_file_type(current_file)

        status = (
            Fore.WHITE + "Target: " +
            Fore.YELLOW + current_file +
            Fore.WHITE + " | Size: " +
            Fore.GREEN + f"{size_kb} KB" +
            Fore.WHITE + " | Type: " +
            Fore.CYAN + file_type
        )

    clean_length = len(strip_ansi(status))
    padding = (cols - clean_length) // 2

    print("\n" + "═" * cols)
    print(" " * padding + status)
    print("═" * cols)
    
def info():
    cols = shutil.get_terminal_size().columns
    block = (
        Fore.CYAN + Style.BRIGHT + "[ INFO ]" + Style.RESET_ALL + "\n"
        + Fore.RED   + "- Name     :                      " + Fore.YELLOW + "ReverseRoom\n"
        + Fore.RED   + "- Version  :                         " + Fore.YELLOW + "0.1\n"
        + Fore.RED   + "- Author   :                      " + Fore.YELLOW + "Orbitz\n"
        + Fore.RED   + "- GitHub   : " + Fore.YELLOW + "https://github.com/Orbitz11\n"
        + Fore.RED   + "- Email    : " + Fore.YELLOW + "orbitz.business11@gmail.com\n"
    )

    for line in block.splitlines():
        print(line.center(cols))

    print((Fore.GREEN + Style.BRIGHT + "[+] Ready to start ..." + Style.RESET_ALL).center(cols))

def show_menu():
    cols = shutil.get_terminal_size().columns
    left_padding = cols // 2 - 20
    right_padding = cols - left_padding - 45  

    print("\n")
    print_centered("═" * 60, Fore.WHITE, Style.DIM)
    print_centered("MAIN MENU", Fore.MAGENTA, Style.BRIGHT)
    print_centered("═" * 60, Fore.WHITE, Style.DIM)
    print()

    menu_options = [
        ("1", "File Type Detector"),
        ("2", "UPX Test"),
        ("3", "Entropy Scanner"),
        ("4", "Import & API Viewer"),
        ("5", "CTF Mode"),
        ("6", "Anti-Debug Check"),
        ("7", "Open Ghidra"),
        ("0", "Exit")
    ]

    for number, name in menu_options:
        if number == "0":
            number_color = Fore.RED + Style.BRIGHT
        else:
            number_color = Fore.GREEN + Style.BRIGHT

        left_line = (
            Fore.WHITE + "[ " +
            number_color + number +
            Fore.WHITE + " ] " +
            Fore.CYAN + name
        )


        if number == "1":
            right_line = (
                Fore.WHITE + "[ " +
                Fore.YELLOW + Style.BRIGHT + "X" +
                Fore.WHITE + " ] " +
                Fore.MAGENTA + "Change File"
            )
            print(" " * left_padding + left_line +
                  " " * right_padding + right_line)
        else:
            print(" " * left_padding + left_line)

    print()

    choose = input(
        " " * left_padding +
        Fore.YELLOW + Style.BRIGHT +
        "Select an option :  "
    )
    return choose.lower()

def change_file():
    new_file = input(Fore.YELLOW + "\nEnter new file path: ").strip()

    if not os.path.exists(new_file):
        print(Fore.RED + "[!] File does not exist.")
        return None

    if not os.path.isfile(new_file):
        print(Fore.RED + "[!] Not a valid file.")
        return None

    print(Fore.GREEN + "[+] Target updated successfully.")
    return new_file

def filetype(file_name):
    try:
        file = subprocess.run(
            ["file", file_name],  
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        print(Fore.GREEN + "\nResult:\n" + file.stdout)
    except FileNotFoundError:
        print(Fore.RED + "\n[file] command not found. Use Linux or install it.")

def ghidra():

    openghidra = subprocess.run(["ghidra"])






def UPXtest(file_name):
    try:
        result = subprocess.run(
            ["upx", "-t", file_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
    except FileNotFoundError:
        print(Fore.RED + "\n[UPX] command not found. Install UPX first.")
        return

    output = result.stdout

    print(Fore.GREEN + "\nResult:\n" + output)


    if result.returncode == 0:
        print(Fore.YELLOW + "\n[+] File appears to be packed with UPX.\n\n")
        print(Fore.WHITE+ "[ " + Fore.GREEN + "1"+ Fore.WHITE +" ]"+ Fore.CYAN + " Unpack file")
        print(Fore.WHITE+ "[ " + Fore.RED + "0"+ Fore.WHITE +" ]"+ Fore.CYAN + " Back to menu")

        choice = input("\nEnter choice: ")

        if choice == "1":
            unpack_file(file_name)
        elif choice == "0":
            return
        else:
            print(Fore.RED + "Invalid choice.")

    else:
        print(Fore.CYAN + "\n[-] File is NOT packed with UPX or test failed.")


def unpack_file(file_name):
    try:
        result = subprocess.run(
            ["upx", "-d", file_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        print(Fore.GREEN + "\nUnpack Result:\n" + result.stdout)
    except FileNotFoundError:
        print(Fore.RED + "[UPX] command not found.")


def main():

    print_header()
    file_name = input(Fore.YELLOW + Style.BRIGHT + "\nEnter the file name to analyze: ")

    while True:

        show_status_bar(file_name)
        choose = show_menu()


        if choose == "0":
            print(Fore.RED + Style.BRIGHT + "\nExiting ReverseRoom...\n")
            break

        elif choose == "1":
            print(Fore.GREEN + "\n[+] File Type Detector selected\n")
            filetype(file_name)

        elif choose == "2":
            print(Fore.GREEN + "\n[+] UPX Test selected\n")
            UPXtest(file_name)

        elif choose == "3":
            print(Fore.GREEN + "\n[+] Entropy Scanner selected\n")

        elif choose == "4":
            print(Fore.GREEN + "\n[+] Import & API Viewer selected\n")

        elif choose == "5":
            print(Fore.GREEN + "\n[+] CTF Mode selected\n")

        elif choose == "6":
            print(Fore.GREEN + "\n[+] Anti-Debug Check selected\n")

        elif choose == "7":
            print(Fore.GREEN + "\n[+] Open Ghidra slected\n")
            ghidra()
            
        elif choose == "x":
            new_target = change_file()
            if new_target:
                file_name = new_target


        else:
            print(Fore.RED + "\n[!] Invalid option\n")

        time.sleep(1)

if __name__ == "__main__":
    main()
