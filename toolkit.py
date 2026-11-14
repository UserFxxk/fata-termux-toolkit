import os
import time
from colorama import Fore, Style, init
from tools.ai import ai_chat

# Inisialisasi colorama agar warna otomatis reset
init(autoreset=True)

def clear():
    os.system("clear")

def pause():
    input(f"\n{Fore.YELLOW}[ Enter untuk kembali ke menu ]")

def header():
    print(Fore.GREEN + "="*40)
    print(Fore.CYAN + "🔥 ELFATHO TOOLKIT V2 - TERMUX UX 😎".center(40))
    print(Fore.GREEN + "="*40)

def has_cmd(cmd):
    return os.system(f"command -v {cmd} > /dev/null 2>&1") == 0

def run_cmd(cmd, pesan):
    print(Fore.BLUE + f"\n[!] {pesan}")
    print(Fore.GREEN + "-"*40)
    os.system(cmd)
    print(Fore.GREEN + "-"*40)
    pause()

def menu():
    print(Fore.YELLOW + "=== FANOX TOOLS KIT ===")
    print("1. Update & Upgrade System")
    print("2. Install Git & Python")
    print("3. Cek Koneksi (Ping)")
    print("4. Info Device (Neofetch)")
    print("5. Cek IP Publik")
    print("6. Catatan Cepat")
    print("7. Bersihkan Sampah (Clean)")
    print("8. AI Chat")
    print(Fore.RED + "0. Exit")

def main():
    try:
        while True:
            clear()
            header()
            menu()
            pilih = input(f"\n{Fore.MAGENTA}Pilih menu (0-8): ").strip()

            if pilih == "1":
                run_cmd("pkg update && pkg upgrade -y", "Mengupdate system...")

            elif pilih == "2":
                run_cmd("pkg install git python -y", "Menginstall Git & Python...")

            elif pilih == "3":
                run_cmd("ping -c 3 google.com", "Testing koneksi...")

            elif pilih == "4":
                if not has_cmd("neofetch"):
                    print(Fore.RED + "Neofetch belum ada. Menginstall...")
                    os.system("pkg install neofetch -y")
                run_cmd("neofetch", "Info Device:")

            elif pilih == "5":
                if not has_cmd("curl"):
                    os.system("pkg install curl -y")
                run_cmd("curl -s ifconfig.me", "IP Publik Kamu:")

            elif pilih == "6":
                note = input(Fore.CYAN + "Tulis catatan: ")
                with open("catatan.txt", "a") as f:
                    f.write(f"[{time.strftime('%d/%m/%Y %H:%M')}] {note}\n")
                print(Fore.GREEN + "✅ Tersimpan di catatan.txt")
                pause()

            elif pilih == "7":
                run_cmd("pkg clean", "Membersihkan cache package...")

            elif pilih == "8":
                ai_chat()

            elif pilih == "0":
                print(Fore.YELLOW + "\nSampai jumpa, mwahhhh! 👋")
                break
            else:
                print(Fore.RED + "Pilihan salah yang bener dong!")
                pause()

    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Program dihentikan. Bye!")

if __name__ == "__main__":
    main()
