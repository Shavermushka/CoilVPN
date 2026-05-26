#!/usr/bin/env python3
# CoilVPN Client - кроссплатформенный
# Для Windows требуется установить TAP-Windows (из OpenVPN) и pytun3

import sys
import os
import threading
import time
import socket
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import requests
import subprocess
import struct
from cryptography.fernet import Fernet

# ========== ОПРЕДЕЛЕНИЕ ПЛАТФОРМЫ ==========
IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform == 'linux'

# ========== ИМПОРТ ПЛАТФОРМО-ЗАВИСИМЫХ МОДУЛЕЙ ==========
if IS_LINUX:
    import fcntl
elif IS_WINDOWS:
    try:
        import pytun3 as pytun  # type: ignore
    except ImportError:
        print("На Windows требуется установить pytun3: pip install pytun3")
        sys.exit(1)

# ========== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ==========
tun = None
udp_sock = None
running = False
peer_map = {}
my_virtual_ip = None
cipher = None
CONFIG_FILE = "config.json"
log_file = open("vpn_client.log", "a")

# ========== ЛОГИРОВАНИЕ ==========
def log(msg):
    timestamp = time.strftime("%H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    log_file.write(line + "\n")
    log_file.flush()

# ========== LINUX TUN (через ioctl) ==========
def create_tun_linux():
    global tun
    TUN_NAME = "vpn0"
    try:
        subprocess.run(["ip", "tuntap", "del", "name", TUN_NAME, "mode", "tun"], stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "tuntap", "add", "name", TUN_NAME, "mode", "tun"], check=True)
        subprocess.run(["ip", "link", "set", TUN_NAME, "up"], check=True)
        fd = os.open("/dev/net/tun", os.O_RDWR)
        IFNAMSIZ = 16
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000
        iface = TUN_NAME.encode() + b"\x00" * (IFNAMSIZ - len(TUN_NAME))
        req = struct.pack("16sH", iface, IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(fd, 0x400454ca, req)
        tun = fd
        log(f"Linux TUN {TUN_NAME} создан")
        return True
    except Exception as e:
        log(f"Ошибка Linux TUN: {e}")
        return False

def configure_network_linux(ip):
    try:
        subprocess.run(["ip", "addr", "add", f"{ip}/24", "dev", "vpn0"], check=True)
        log(f"IP {ip}/24 назначен")
        return True
    except Exception as e:
        log(f"Ошибка назначения IP: {e}")
        return False

def delete_tun_linux():
    global tun
    if tun:
        os.close(tun)
        tun = None
    subprocess.run(["ip", "tuntap", "del", "name", "vpn0", "mode", "tun"], stderr=subprocess.DEVNULL)

def tun_reader_linux():
    global tun, running
    while running and tun:
        try:
            packet = os.read(tun, 65535)
            if len(packet) >= 20:
                dst_ip = socket.inet_ntoa(packet[16:20])
                if dst_ip in peer_map:
                    ip, port = peer_map[dst_ip]
                    encrypted = cipher.encrypt(packet)
                    udp_sock.sendto(encrypted, (ip, port))
        except OSError:
            break
        except Exception as e:
            if running:
                log(f"tun_reader: {e}")

def tun_writer_linux(packet):
    if tun:
        os.write(tun, packet)

# ========== WINDOWS TAP (через pytun3) ==========
def create_tun_windows():
    global tun
    try:
        tun = pytun.TunTapDevice(flags=pytun.IFF_TAP)
        tun.addr = my_virtual_ip
        tun.netmask = "255.255.255.0"
        tun.up()
        log(f"Windows TAP создан: {tun.name} IP {my_virtual_ip}")
        return True
    except Exception as e:
        log(f"Ошибка создания TAP: {e}")
        return False

def delete_tun_windows():
    global tun
    if tun:
        tun.down()
        tun.close()
        tun = None
        log("Windows TAP удалён")

def tun_reader_windows():
    global tun, running
    while running and tun:
        try:
            packet = tun.read(65535)
            if len(packet) >= 20:
                dst_ip = socket.inet_ntoa(packet[16:20])
                if dst_ip in peer_map:
                    ip, port = peer_map[dst_ip]
                    encrypted = cipher.encrypt(packet)
                    udp_sock.sendto(encrypted, (ip, port))
        except Exception as e:
            if running:
                log(f"tun_reader_windows: {e}")

def tun_writer_windows(packet):
    if tun:
        tun.write(packet)

# ========== ОБЩИЕ ФУНКЦИИ (UDP, регистрация) ==========
def start_udp_listener(port):
    global udp_sock
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("0.0.0.0", port))
    log(f"UDP слушает {port}")
    while running:
        try:
            data, addr = udp_sock.recvfrom(65535)
            decrypted = cipher.decrypt(data)
            if IS_LINUX:
                tun_writer_linux(decrypted)
            else:
                tun_writer_windows(decrypted)
        except Exception as e:
            if running:
                log(f"UDP ошибка: {e}")

def register(server_url, username, port):
    global my_virtual_ip, peer_map
    try:
        resp = requests.post(f"{server_url}/register", json={"username": username, "port": port}, timeout=3)
        data = resp.json()
        if data.get("status") == "ok":
            my_virtual_ip = data["virtual_ip"]
            peer_map.clear()
            for p in data.get("peers", []):
                peer_map[p["virtual_ip"]] = (p["ip"], p["port"])
            log(f"Регистрация: {username} -> {my_virtual_ip}")
            return True
        else:
            log(f"Ошибка рег: {data}")
            return False
    except Exception as e:
        log(f"Ошибка сервера: {e}")
        return False

def unregister(server_url, username):
    try:
        requests.post(f"{server_url}/unregister", json={"username": username}, timeout=2)
    except:
        pass

def refresh_peers(server_url, username):
    global peer_map
    while running:
        time.sleep(10)
        try:
            resp = requests.get(f"{server_url}/refresh", timeout=3)
            all_peers = resp.json()
            new_map = {}
            for p in all_peers:
                if p["name"] != username:
                    new_map[p["virtual_ip"]] = (p["ip"], p["port"])
            peer_map.clear()
            peer_map.update(new_map)
            log(f"Активные пиры: {list(peer_map.keys())}")
        except Exception as e:
            log(f"Ошибка обновления: {e}")

# ========== ГРАФИЧЕСКИЙ ИНТЕРФЕЙС ==========
class VpnGUI:
    def __init__(self, root):
        self.root = root
        root.title("CoilVPN Client")
        root.geometry("550x500")

        self.config = self.load_config()

        # Рамка настроек
        frame = ttk.LabelFrame(root, text="Настройки подключения")
        frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(frame, text="Имя игрока:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.entry_name = tk.Entry(frame, width=20)
        self.entry_name.grid(row=0, column=1, padx=5, pady=2)
        self.entry_name.insert(0, self.config.get("username", "Player"))

        tk.Label(frame, text="UDP порт (локальный):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.entry_port = tk.Entry(frame, width=10)
        self.entry_port.grid(row=1, column=1, padx=5, pady=2)
        self.entry_port.insert(0, str(self.config.get("port", 5000)))

        tk.Label(frame, text="Адрес сервера (http://IP:8005):").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.entry_server = tk.Entry(frame, width=35)
        self.entry_server.grid(row=2, column=1, padx=5, pady=2)
        self.entry_server.insert(0, self.config.get("server_url", "http://192.168.0.107:8005"))

        # Кнопки
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)
        self.connect_btn = tk.Button(btn_frame, text="Подключиться", command=self.connect, bg="lightgreen", width=15)
        self.connect_btn.pack(side="left", padx=5)
        self.disconnect_btn = tk.Button(btn_frame, text="Отключиться", command=self.disconnect, state="disabled", bg="salmon", width=15)
        self.disconnect_btn.pack(side="left", padx=5)

        self.status_label = tk.Label(root, text="Не подключён", fg="red")
        self.status_label.pack()
        self.ip_label = tk.Label(root, text="Виртуальный IP: --")
        self.ip_label.pack()

        tk.Label(root, text="Участники сети (виртуальные IP):").pack()
        self.peer_listbox = tk.Listbox(root, height=8)
        self.peer_listbox.pack(fill="both", expand=True, padx=10, pady=5)

        tk.Label(root, text="Лог событий:").pack()
        self.log_text = scrolledtext.ScrolledText(root, height=8, state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_config(self):
        cfg = {
            "username": self.entry_name.get(),
            "port": int(self.entry_port.get()),
            "server_url": self.entry_server.get()
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=4)

    def log_gui(self, msg):
        self.log_text.config(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def update_ui(self):
        self.ip_label.config(text=f"Виртуальный IP: {my_virtual_ip if my_virtual_ip else '--'}")
        self.peer_listbox.delete(0, "end")
        for vip, (ip, port) in peer_map.items():
            self.peer_listbox.insert("end", f"{vip}  ({ip}:{port})")

    def update_peers_loop(self):
        if running:
            self.update_ui()
            self.root.after(3000, self.update_peers_loop)

    def connect(self):
        global running, cipher, tun, my_virtual_ip
        if running:
            return
        self.save_config()
        username = self.entry_name.get().strip()
        if not username:
            messagebox.showerror("Ошибка", "Введите имя")
            return
        try:
            port = int(self.entry_port.get())
            if port < 1024 or port > 65535:
                raise ValueError
        except:
            messagebox.showerror("Ошибка", "Порт должен быть от 1024 до 65535")
            return
        server_url = self.entry_server.get().strip()
        if not server_url.startswith("http"):
            server_url = "http://" + server_url

        # Генерация ключа шифрования (один для всех)
        cipher = Fernet(Fernet.generate_key())

        # Регистрация
        if not register(server_url, username, port):
            messagebox.showerror("Ошибка", "Не удалось зарегистрироваться. Проверьте сервер.")
            return

        # Создание TUN/TAP
        if IS_LINUX:
            if not create_tun_linux():
                unregister(server_url, username)
                messagebox.showerror("Ошибка", "Не удалось создать TUN (Linux). Запустите с sudo и проверьте ip tuntap.")
                return
            if not configure_network_linux(my_virtual_ip):
                delete_tun_linux()
                unregister(server_url, username)
                messagebox.showerror("Ошибка", "Не удалось назначить IP.")
                return
        else:  # Windows
            if not create_tun_windows():
                unregister(server_url, username)
                messagebox.showerror("Ошибка", "Не удалось создать TAP. Установите TAP-Windows (OpenVPN) и pytun3.")
                return

        # Запуск потоков
        running = True
        threading.Thread(target=start_udp_listener, args=(port,), daemon=True).start()
        if IS_LINUX:
            threading.Thread(target=tun_reader_linux, daemon=True).start()
        else:
            threading.Thread(target=tun_reader_windows, daemon=True).start()
        threading.Thread(target=refresh_peers, args=(server_url, username), daemon=True).start()

        self.status_label.config(text="Подключён", fg="green")
        self.connect_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")
        self.log_gui(f"Подключено! Ваш виртуальный IP: {my_virtual_ip}")
        self.update_peers_loop()

    def disconnect(self):
        global running, tun, udp_sock
        if not running:
            return
        running = False
        time.sleep(0.5)
        if udp_sock:
            udp_sock.close()
        if IS_LINUX:
            delete_tun_linux()
        else:
            delete_tun_windows()
        unregister(self.entry_server.get(), self.entry_name.get())
        self.status_label.config(text="Не подключён", fg="red")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")
        self.ip_label.config(text="Виртуальный IP: --")
        self.log_gui("Отключено.")

    def on_close(self):
        self.disconnect()
        log_file.close()
        self.root.destroy()

if __name__ == "__main__":
    if IS_LINUX and os.geteuid() != 0:
        print("На Linux нужны права root: sudo venv/bin/python vpn_client.py")
        sys.exit(1)
    root = tk.Tk()
    app = VpnGUI(root)
    root.mainloop()