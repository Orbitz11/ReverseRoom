import shutil
from colorama import Fore, Style, init
import subprocess
import time
          
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
        ("0", "Exit")
    ]

    for number, name in menu_options:

        if number == "0":
            number_color = Fore.RED + Style.BRIGHT
        else:
            number_color = Fore.GREEN + Style.BRIGHT

        line = (
            Fore.WHITE + "[ " +
            number_color + number +
            Fore.WHITE + " ] " +
            Fore.CYAN + name
        )

        print(" " * left_padding + line)

    print()

    choose = input(" " * left_padding + Fore.YELLOW + Style.BRIGHT + "Select an option :  ")
    return choose

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


    file_result = file.stdout
    file_ret = file.returncode

    print(":")
    print(file)


def main():

    print_header()
    file_name = input(Fore.YELLOW + Style.BRIGHT + "\nEnter the file name to analyze: ")
    
    while True:
        choose = show_menu()

        if choose == "0":
            print(Fore.RED + Style.BRIGHT + "\nExiting ReverseRoom...\n")
            break

        elif choose == "1":
            print(Fore.GREEN + "\n[+] File Type Detector selected\n")
            filetype(file_name)

        elif choose == "2":
            print(Fore.GREEN + "\n[+] UPX Test selected\n")

        elif choose == "3":
            print(Fore.GREEN + "\n[+] Entropy Scanner selected\n")

        elif choose == "4":
            print(Fore.GREEN + "\n[+] Import & API Viewer selected\n")

        elif choose == "5":
            print(Fore.GREEN + "\n[+] CTF Mode selected\n")

        elif choose == "6":
            print(Fore.GREEN + "\n[+] Anti-Debug Check selected\n")

        else:
            print(Fore.RED + "\n[!] Invalid option\n")

        time.sleep(1)

if __name__ == "__main__":
    main()
