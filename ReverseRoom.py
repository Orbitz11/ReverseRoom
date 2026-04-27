import math
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style, init
except ImportError:
    print("[!] Missing dependency: colorama")
    print("Install it with: pip install colorama")
    raise SystemExit(1)

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

FLAG_REGEX = re.compile(rb"(?:picoCTF|flag|ctf|THAWD|HTB|DUCTF|flag)\{[^}\r\n]{3,120}\}", re.IGNORECASE)
SUSPICIOUS_WORDS = [
    b"ptrace", b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"OutputDebugString",
    b"NtQueryInformationProcess", b"/proc/self/status", b"TracerPid", b"debugger",
    b"anti-debug", b"BeingDebugged", b"PEB", b"rdtsc", b"qemu", b"vmware",
    b"virtualbox", b"frida", b"gdb", b"strace", b"ltrace"
]


def print_centered(text, color=Fore.WHITE, style=Style.NORMAL):
    cols = shutil.get_terminal_size((100, 20)).columns
    for line in text.splitlines():
        print(color + style + line.center(cols) + Style.RESET_ALL)


def print_header():
    print_centered(logo, Fore.RED, Style.BRIGHT)
    binary_text = "01010010 01100101 01110110 01100101 01110010 01110011 01100101 01010010 01101111 01101111 01101101\n"
    print_centered(binary_text, Fore.GREEN, Style.BRIGHT)
    time.sleep(0.3)
    info()


def strip_ansi(text):
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text)


def run_cmd(command, timeout=15):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout
    except FileNotFoundError:
        return 127, f"[!] Command not found: {command[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"[!] Command timed out: {' '.join(command)}"
    except Exception as exc:
        return 1, f"[!] Error: {exc}"


def valid_target(file_name):
    return bool(file_name) and os.path.isfile(file_name)


def require_target(file_name):
    if not valid_target(file_name):
        print(Fore.RED + "[!] Select a valid file first. Press X from the menu to change target.")
        return False
    return True


def get_file_type(file_path):
    if not valid_target(file_path):
        return "Unknown"

    code, output = run_cmd(["file", file_path])
    output_l = output.lower()

    if code == 127:
        return "Unknown"
    if "pe32" in output_l or "windows" in output_l:
        return "PE"
    if "elf" in output_l:
        return "ELF"
    if "mach-o" in output_l:
        return "Mach-O"
    return "Unknown"


def show_status_bar(current_file):
    cols = shutil.get_terminal_size((100, 20)).columns

    if not valid_target(current_file):
        status = Fore.RED + "No valid file selected"
    else:
        size = os.path.getsize(current_file)
        size_kb = round(size / 1024, 2)
        file_type = get_file_type(current_file)
        status = (
            Fore.WHITE + "Target: " + Fore.YELLOW + current_file +
            Fore.WHITE + " | Size: " + Fore.GREEN + f"{size_kb} KB" +
            Fore.WHITE + " | Type: " + Fore.CYAN + file_type
        )

    clean_length = len(strip_ansi(status))
    padding = max((cols - clean_length) // 2, 0)

    print("\n" + "═" * cols)
    print(" " * padding + status)
    print("═" * cols)


def info():
    cols = shutil.get_terminal_size((100, 20)).columns
    block = (
        Fore.CYAN + Style.BRIGHT + "[ INFO ]" + Style.RESET_ALL + "\n"
        + Fore.RED + "- Name     :                      " + Fore.YELLOW + "ReverseRoom\n"
        + Fore.RED + "- Version  :                         " + Fore.YELLOW + "0.2\n"
        + Fore.RED + "- Author   :                      " + Fore.YELLOW + "Orbitz\n"
        + Fore.RED + "- GitHub   : " + Fore.YELLOW + "https://github.com/Orbitz11\n"
        + Fore.RED + "- Email    : " + Fore.YELLOW + "orbitz.business11@gmail.com\n"
    )

    for line in block.splitlines():
        print(line.center(cols))

    print((Fore.GREEN + Style.BRIGHT + "[+] Ready to start ..." + Style.RESET_ALL).center(cols))


def show_menu():
    cols = shutil.get_terminal_size((100, 20)).columns
    left_padding = max(cols // 2 - 20, 0)
    right_padding = max(cols - left_padding - 45, 2)

    print("\n")
    print_centered("═" * 60, Fore.WHITE, Style.DIM)
    print_centered("MAIN MENU", Fore.MAGENTA, Style.BRIGHT)
    print_centered("═" * 60, Fore.WHITE, Style.DIM)
    print()

    menu_options = [
        ("01", "File Type Detector"),
        ("02", "UPX Test / Unpack"),
        ("03", "Entropy Scanner"),
        ("04", "Import & API Viewer"),
        ("05", "CTF Mode"),
        ("06", "Anti-Debug Check"),
        ("07", "Open Ghidra"),
        ("08", "Change Mode (chmod +x)"),
        ("09", "Show Strings"),
        ("10", "Generate Analysis Report"),
        ("00", "Exit"),
    ]

    for number, name in menu_options:
        number_color = Fore.RED + Style.BRIGHT if number == "00" else Fore.GREEN + Style.BRIGHT
        left_line = Fore.WHITE + "[ " + number_color + number + Fore.WHITE + " ] " + Fore.CYAN + name

        if number == "01":
            right_line = Fore.WHITE + "[ " + Fore.YELLOW + Style.BRIGHT + "X" + Fore.WHITE + " ] " + Fore.MAGENTA + "Change File"
            print(" " * left_padding + left_line + " " * right_padding + right_line)
        else:
            print(" " * left_padding + left_line)

    print()
    return input(" " * left_padding + Fore.YELLOW + Style.BRIGHT + "Select an option :  ").strip().lower()


def change_file():
    new_file = input(Fore.YELLOW + "\nEnter new file path: ").strip().strip('"').strip("'")

    if not os.path.exists(new_file):
        print(Fore.RED + "[!] File does not exist.")
        return None
    if not os.path.isfile(new_file):
        print(Fore.RED + "[!] Not a valid file.")
        return None

    print(Fore.GREEN + "[+] Target updated successfully.")
    return new_file


def filetype(file_name):
    if not require_target(file_name):
        return ""
    code, output = run_cmd(["file", file_name])
    print(Fore.GREEN + "\nResult:\n" + output)
    return output


def chmod_file(file_name):
    if not require_target(file_name):
        return
    code, output = run_cmd(["chmod", "+x", file_name])
    if code == 0:
        print(Fore.GREEN + "[+] chmod +x applied successfully.")
    else:
        print(Fore.RED + output)


def ghidra(file_name=None):
    command = ["ghidra"]
    if file_name and valid_target(file_name):
        command.append(file_name)
    code, output = run_cmd(command, timeout=5)
    if code == 127:
        print(Fore.RED + "[!] Ghidra command not found. Try opening ghidraRun manually or add it to PATH.")
    elif output:
        print(output)


def extract_strings(file_name, min_len=4):
    if not valid_target(file_name):
        return []
    data = Path(file_name).read_bytes()
    pattern = rb"[ -~]{" + str(min_len).encode() + rb",}"
    return [s.decode("utf-8", errors="ignore") for s in re.findall(pattern, data)]


def strings_view(file_name):
    if not require_target(file_name):
        return []

    code, output = run_cmd(["strings", file_name], timeout=20)
    if code == 127:
        print(Fore.YELLOW + "[!] strings command not found. Using Python fallback.\n")
        found = extract_strings(file_name)
        output = "\n".join(found)
    else:
        found = output.splitlines()

    print(Fore.GREEN + "\nResult:\n" + output[:20000])
    if len(output) > 20000:
        print(Fore.YELLOW + "\n[!] Output trimmed to first 20000 characters.")
    recommended_search(found)
    return found


def recommended_search(strings_list):
    choice = input(Fore.YELLOW + "\nDo you want to search inside strings? (Y/N): ").strip().lower()
    if choice != "y":
        return

    term = input(Fore.YELLOW + "Enter keyword/regex, or press Enter for common CTF keywords: ").strip()
    if not term:
        term = r"flag|pico|ctf|key|pass|password|secret|token|admin|UPX"

    try:
        regex = re.compile(term, re.IGNORECASE)
    except re.error:
        regex = re.compile(re.escape(term), re.IGNORECASE)

    matches = [s for s in strings_list if regex.search(s)]
    if not matches:
        print(Fore.RED + "[-] No matches found.")
        return

    print(Fore.GREEN + f"\n[+] Found {len(matches)} match(es):\n")
    for line in matches[:200]:
        print(Fore.CYAN + line)
    if len(matches) > 200:
        print(Fore.YELLOW + "[!] Showing first 200 matches only.")


def UPXtest(file_name):
    if not require_target(file_name):
        return

    code, output = run_cmd(["upx", "-t", file_name], timeout=20)
    if code == 127:
        print(Fore.RED + "\n[UPX] command not found. Install UPX first.")
        return

    print(Fore.GREEN + "\nResult:\n" + output)

    if code == 0:
        print(Fore.YELLOW + "\n[+] File appears to be packed with UPX.\n")
        print(Fore.WHITE + "[ " + Fore.GREEN + "1" + Fore.WHITE + " ]" + Fore.CYAN + " Unpack file")
        print(Fore.WHITE + "[ " + Fore.RED + "0" + Fore.WHITE + " ]" + Fore.CYAN + " Back to menu")

        choice = input("\nEnter choice: ").strip()
        if choice == "1":
            unpack_file(file_name)
        elif choice != "0":
            print(Fore.RED + "Invalid choice.")
    else:
        print(Fore.CYAN + "\n[-] File is NOT packed with UPX or the test failed.")


def unpack_file(file_name):
    code, output = run_cmd(["upx", "-d", file_name], timeout=30)
    print(Fore.GREEN + "\nUnpack Result:\n" + output)


def calculate_entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def entropy_scanner(file_name, chunk_size=4096):
    if not require_target(file_name):
        return []

    data = Path(file_name).read_bytes()
    total_entropy = calculate_entropy(data)
    print(Fore.GREEN + f"\n[+] Overall entropy: {total_entropy:.4f} / 8.0000")

    if total_entropy >= 7.2:
        print(Fore.YELLOW + "[!] High entropy. File may be packed, encrypted, or compressed.")
    elif total_entropy <= 1.0:
        print(Fore.CYAN + "[-] Very low entropy. File contains lots of repeated/empty data.")
    else:
        print(Fore.CYAN + "[-] Entropy looks normal-ish. Not enough alone to prove packing.")

    suspicious_chunks = []
    for offset in range(0, len(data), chunk_size):
        chunk = data[offset:offset + chunk_size]
        ent = calculate_entropy(chunk)
        if ent >= 7.2:
            suspicious_chunks.append((offset, ent))

    if suspicious_chunks:
        print(Fore.YELLOW + "\nHigh-entropy chunks:")
        for offset, ent in suspicious_chunks[:30]:
            print(Fore.WHITE + f"  0x{offset:08x}  entropy={ent:.4f}")
        if len(suspicious_chunks) > 30:
            print(Fore.YELLOW + "[!] Showing first 30 chunks only.")
    return [("overall", total_entropy), *suspicious_chunks]


def imports_api_viewer(file_name):
    if not require_target(file_name):
        return ""

    ftype = get_file_type(file_name)
    print(Fore.GREEN + f"\n[+] Detected type: {ftype}\n")

    commands = []
    if ftype == "ELF":
        commands = [["readelf", "-Ws", file_name], ["objdump", "-T", file_name]]
    elif ftype == "PE":
        commands = [["objdump", "-p", file_name], ["rabin2", "-i", file_name]]
    elif ftype == "Mach-O":
        commands = [["otool", "-L", file_name], ["nm", "-m", file_name]]
    else:
        commands = [["rabin2", "-i", file_name], ["objdump", "-p", file_name]]

    final_output = []
    for cmd in commands:
        code, output = run_cmd(cmd, timeout=20)
        if code == 127:
            final_output.append(output)
            continue
        if output.strip():
            final_output.append(f"$ {' '.join(cmd)}\n{output}")
            break

    if not final_output or all("Command not found" in x for x in final_output):
        fallback = strings_import_fallback(file_name)
        print(fallback)
        return fallback

    result = "\n".join(final_output)
    print(Fore.CYAN + result[:20000])
    if len(result) > 20000:
        print(Fore.YELLOW + "\n[!] Output trimmed to first 20000 characters.")
    return result


def strings_import_fallback(file_name):
    found = extract_strings(file_name)
    keywords = ["CreateFile", "ReadFile", "WriteFile", "socket", "connect", "recv", "send", "printf", "scanf", "strcmp", "memcmp", "strlen", "ptrace", "VirtualAlloc", "LoadLibrary", "GetProcAddress"]
    hits = [s for s in found if any(k.lower() in s.lower() for k in keywords)]
    lines = [Fore.YELLOW + "[!] Import tools not available. Showing API-like strings fallback:\n"]
    lines += [Fore.CYAN + h for h in hits[:200]]
    if not hits:
        lines.append(Fore.RED + "[-] No obvious API strings found.")
    return "\n".join(lines)


def ctf_mode(file_name):
    if not require_target(file_name):
        return []

    data = Path(file_name).read_bytes()
    flags = sorted(set(m.group(0).decode("utf-8", errors="ignore") for m in FLAG_REGEX.finditer(data)))
    found_strings = extract_strings(file_name)
    keyword_regex = re.compile(r"flag|pico|ctf|password|pass|secret|key|token|admin|correct|wrong|fail|success", re.IGNORECASE)
    interesting = [s for s in found_strings if keyword_regex.search(s)]

    print(Fore.GREEN + "\n[+] CTF quick scan results\n")

    if flags:
        print(Fore.YELLOW + "Possible flag(s):")
        for flag in flags:
            print(Fore.GREEN + "  " + flag)
    else:
        print(Fore.CYAN + "[-] No direct flag pattern found.")

    print(Fore.YELLOW + "\nInteresting strings:")
    if interesting:
        for line in interesting[:150]:
            print(Fore.CYAN + "  " + line)
        if len(interesting) > 150:
            print(Fore.YELLOW + "[!] Showing first 150 interesting strings only.")
    else:
        print(Fore.RED + "  No obvious CTF keywords found.")

    print(Fore.YELLOW + "\nSuggested next steps:")
    print(Fore.WHITE + "  - If packed: use option 02 to unpack UPX.")
    print(Fore.WHITE + "  - If strcmp/memcmp appears: debug around comparison points.")
    print(Fore.WHITE + "  - If high entropy: check unpacking/encryption routines.")
    print(Fore.WHITE + "  - Try: ltrace ./binary or gdb with breakpoints on strcmp/memcmp/puts.")
    return flags + interesting


def anti_debug_check(file_name):
    if not require_target(file_name):
        return []

    data = Path(file_name).read_bytes().lower()
    hits = []
    for word in SUSPICIOUS_WORDS:
        if word.lower() in data:
            hits.append(word.decode("utf-8", errors="ignore"))

    print(Fore.GREEN + "\n[+] Anti-debug / anti-VM indicators\n")
    if not hits:
        print(Fore.CYAN + "[-] No obvious anti-debug strings found.")
    else:
        for hit in sorted(set(hits)):
            print(Fore.YELLOW + "  [!] " + hit)

    ftype = get_file_type(file_name)
    if ftype == "ELF":
        print(Fore.WHITE + "\nTip: run `ltrace ./file` or break on `ptrace` in gdb if ptrace exists.")
    elif ftype == "PE":
        print(Fore.WHITE + "\nTip: check imports for IsDebuggerPresent / NtQueryInformationProcess in x64dbg.")
    return hits


def generate_report(file_name):
    if not require_target(file_name):
        return None

    target = Path(file_name)
    report_name = f"ReverseRoom_report_{target.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    report_path = target.parent / report_name

    data = target.read_bytes()
    ftype_text = filetype_collect(file_name)
    entropy = calculate_entropy(data)
    found_strings = extract_strings(file_name)
    flags = sorted(set(m.group(0).decode("utf-8", errors="ignore") for m in FLAG_REGEX.finditer(data)))
    anti_hits = [w.decode("utf-8", errors="ignore") for w in SUSPICIOUS_WORDS if w.lower() in data.lower()]
    interesting_regex = re.compile(r"flag|pico|ctf|password|pass|secret|key|token|admin|correct|wrong|fail|success|UPX", re.IGNORECASE)
    interesting = [s for s in found_strings if interesting_regex.search(s)]

    content = []
    content.append("ReverseRoom Analysis Report")
    content.append("=" * 30)
    content.append(f"Generated: {datetime.now()}")
    content.append(f"Target: {target}")
    content.append(f"Size: {target.stat().st_size} bytes")
    content.append(f"Detected Type: {get_file_type(file_name)}")
    content.append("\n[file output]")
    content.append(ftype_text.strip())
    content.append(f"\nEntropy: {entropy:.4f} / 8.0000")
    content.append("Assessment: " + ("High entropy; possible packing/encryption/compression." if entropy >= 7.2 else "No high overall entropy indicator."))
    content.append("\nPossible Flags:")
    content.extend(flags if flags else ["None found"])
    content.append("\nAnti-debug / Anti-VM Indicators:")
    content.extend(sorted(set(anti_hits)) if anti_hits else ["None found"])
    content.append("\nInteresting Strings:")
    content.extend(interesting[:300] if interesting else ["None found"])
    content.append("\nTop 100 Strings:")
    content.extend(found_strings[:100] if found_strings else ["None found"])

    report_path.write_text("\n".join(content), encoding="utf-8", errors="ignore")
    print(Fore.GREEN + f"\n[+] Report saved to: {report_path}")
    return str(report_path)


def filetype_collect(file_name):
    code, output = run_cmd(["file", file_name])
    return output


def main():
    print_header()
    file_name = input(Fore.YELLOW + Style.BRIGHT + "\nEnter the file name to analyze: ").strip().strip('"').strip("'")

    while True:
        show_status_bar(file_name)
        choose = show_menu()

        if choose in {"0", "00", "exit", "q", "quit"}:
            print(Fore.RED + Style.BRIGHT + "\nExiting ReverseRoom...\n")
            break
        elif choose in {"1", "01"}:
            print(Fore.GREEN + "\n[+] File Type Detector selected\n")
            filetype(file_name)
        elif choose in {"2", "02"}:
            print(Fore.GREEN + "\n[+] UPX Test selected\n")
            UPXtest(file_name)
        elif choose in {"3", "03"}:
            print(Fore.GREEN + "\n[+] Entropy Scanner selected\n")
            entropy_scanner(file_name)
        elif choose in {"4", "04"}:
            print(Fore.GREEN + "\n[+] Import & API Viewer selected\n")
            imports_api_viewer(file_name)
        elif choose in {"5", "05"}:
            print(Fore.GREEN + "\n[+] CTF Mode selected\n")
            ctf_mode(file_name)
        elif choose in {"6", "06"}:
            print(Fore.GREEN + "\n[+] Anti-Debug Check selected\n")
            anti_debug_check(file_name)
        elif choose in {"7", "07"}:
            print(Fore.GREEN + "\n[+] Open Ghidra selected\n")
            ghidra(file_name)
        elif choose in {"8", "08"}:
            print(Fore.GREEN + "\n[+] Change Mode (chmod) selected\n")
            chmod_file(file_name)
        elif choose in {"9", "09"}:
            print(Fore.GREEN + "\n[+] Show Strings selected\n")
            strings_view(file_name)
        elif choose == "10":
            print(Fore.GREEN + "\n[+] Generate Analysis Report selected\n")
            generate_report(file_name)
        elif choose == "x":
            new_target = change_file()
            if new_target:
                file_name = new_target
        else:
            print(Fore.RED + "\n[!] Invalid option\n")

        input(Fore.WHITE + Style.DIM + "\nPress Enter to continue...")


if __name__ == "__main__":
    main()
