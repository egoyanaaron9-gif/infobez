import os
import json
import shutil
import hashlib
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
from cryptography.fernet import Fernet

DATA_DIR = "data"
KEY_FILE = os.path.join(DATA_DIR, "secret.key")
DATA_FILE = os.path.join(DATA_DIR, "db.json")
LOG_FILE = os.path.join(DATA_DIR, "logs.json")

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_key():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)

def load_key():
    return open(KEY_FILE, "rb").read()

def get_cipher():
    return Fernet(load_key())

def calculate_checksum(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def backup_file(file_path):
    if os.path.exists(file_path):
        backup_path = file_path + ".bak"
        shutil.copy(file_path, backup_path)

def save_data(data, file_path):
    backup_file(file_path)
    cipher = get_cipher()
    json_data = json.dumps(data, ensure_ascii=False).encode('utf-8')
    encrypted_data = cipher.encrypt(json_data)
    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    # Сохраняем контрольную сумму файла
    checksum = calculate_checksum(file_path)
    with open(file_path + ".sha256", "w") as f:
        f.write(checksum)

def load_data(file_path):
    if not os.path.exists(file_path):
        return None

    # Проверка целостности
    checksum_file = file_path + ".sha256"
    if os.path.exists(checksum_file):
        with open(checksum_file, "r") as f:
            expected_checksum = f.read().strip()
        actual_checksum = calculate_checksum(file_path)
        if expected_checksum != actual_checksum:
            raise ValueError(f"ОШИБКА ЦЕЛОСТНОСТИ! Файл был поврежден или изменен вручную: {file_path}")

    cipher = get_cipher()
    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    try:
        json_data = cipher.decrypt(encrypted_data).decode('utf-8')
        return json.loads(json_data)
    except Exception:
        raise ValueError("Ошибка расшифровки данных. Возможно используется неверный ключ.")

def log_action(user, action):
    logs = load_data(LOG_FILE) or []
    logs.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "action": action
    })
    save_data(logs, LOG_FILE)

def init_db():
    generate_key()

    if not os.path.exists(DATA_FILE):
        default_data = {
            "users": {
                "admin": {"password_hash": hash_password("admin"), "role": "Admin"},
                "user": {"password_hash": hash_password("user"), "role": "User"}
            },
            "clients": [],
            "computers": {
                "PC-1": {"status": "free", "client": None, "end_time": None},
                "PC-2": {"status": "free", "client": None, "end_time": None},
                "PC-3": {"status": "free", "client": None, "end_time": None},
                "PC-4": {"status": "free", "client": None, "end_time": None},
                "PC-5": {"status": "free", "client": None, "end_time": None},
                "PC-6": {"status": "free", "client": None, "end_time": None}
            }
        }
        save_data(default_data, DATA_FILE)
    if not os.path.exists(LOG_FILE):
        save_data([], LOG_FILE)


class LoginWindow:
    def __init__(self, root, on_success):
        self.root = root
        self.on_success = on_success
        self.frame = tk.Frame(root)
        self.frame.pack(pady=50)

        tk.Label(self.frame, text="ИС GamePoint", font=("Arial", 20, "bold")).pack(pady=10)
        tk.Label(self.frame, text="Авторизация", font=("Arial", 12)).pack(pady=5)

        tk.Label(self.frame, text="Логин (admin/user):").pack()
        self.login_entry = tk.Entry(self.frame)
        self.login_entry.pack()
        self.login_entry.insert(0, "admin")

        tk.Label(self.frame, text="Пароль:").pack()
        self.password_entry = tk.Entry(self.frame, show="*")
        self.password_entry.pack()
        self.password_entry.insert(0, "admin")

        tk.Button(self.frame, text="Войти", command=self.login, width=20).pack(pady=20)

    def login(self):
        login = self.login_entry.get()
        pwd = self.password_entry.get()
        try:
            db = load_data(DATA_FILE)
            user_data = db["users"].get(login)
            if user_data and user_data["password_hash"] == hash_password(pwd):
                log_action(login, "Успешный вход в систему")
                self.frame.destroy()
                self.on_success(login, user_data["role"], db)
            else:
                log_action(login, "Неудачная попытка входа")
                messagebox.showerror("Ошибка", "Неверный логин или пароль")
        except Exception as e:
            messagebox.showerror("Критическая ошибка безопасности", str(e))

class AppWindow:
    def __init__(self, root, current_user, user_role, db):
        self.root = root
        self.current_user = current_user
        self.user_role = user_role
        self.db = db

        self.frame = tk.Frame(root)
        self.frame.pack(fill=tk.BOTH, expand=True)

        top_frame = tk.Frame(self.frame)
        top_frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(top_frame, text=f"Пользователь: {self.current_user} (Роль: {self.user_role})", font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        tk.Button(top_frame, text="Выйти", command=self.logout).pack(side=tk.RIGHT)

        self.notebook = ttk.Notebook(self.frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tab_computers = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_computers, text="Управление компьютерами")
        self.build_computers_tab()

        if self.user_role == "Admin":
            self.tab_logs = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_logs, text="Логи безопасности")
            self.build_logs_tab()

        self.check_expired_sessions()

    def build_computers_tab(self):
        for widget in self.tab_computers.winfo_children():
            widget.destroy()

        row, col = 0, 0
        for pc_id, info in self.db["computers"].items():
            f = tk.LabelFrame(self.tab_computers, text=pc_id, width=180, height=130)
            f.grid(row=row, column=col, padx=10, pady=10)
            f.grid_propagate(False)

            status = info["status"]
            client = info.get("client", "-")

            tk.Label(f, text=f"Статус: {'Занят' if status == 'busy' else 'Свободен'}").pack(pady=5)
            tk.Label(f, text=f"Клиент: {client}").pack(pady=5)

            if status == "busy" and info.get("end_time"):
                tk.Label(f, text=f"До: {info['end_time']}").pack(pady=2)

            if status == "free":
                tk.Button(f, text="Занять место", command=lambda p=pc_id: self.rent_pc(p)).pack()
            else:
                tk.Button(f, text="Освободить", command=lambda p=pc_id: self.free_pc(p)).pack()

            col +=1
            if col > 2:
                col = 0
                row += 1

    def build_logs_tab(self):
        if self.user_role != "Admin":
            return
        for widget in self.tab_logs.winfo_children():
            widget.destroy()

        listbox = tk.Listbox(self.tab_logs)
        listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        try:
            logs = load_data(LOG_FILE)
            if logs:
                for log in reversed(logs):
                    listbox.insert(tk.END, f"{log['timestamp']} | УЗ: {log['user']} | Действие: {log['action']}")
        except Exception as e:
            listbox.insert(tk.END, f"Ошибка загрузки логов: {e}")

        tk.Button(self.tab_logs, text="Обновить", command=self.build_logs_tab).pack(pady=5)

    def check_expired_sessions(self):
        now = datetime.now()
        changed = False
        for pc_id, info in self.db["computers"].items():
            if info.get("status") == "busy" and info.get("end_time"):
                try:
                    end_time_dt = datetime.strptime(info["end_time"], "%Y-%m-%d %H:%M")
                    if now >= end_time_dt:
                        client_name = info.get("client", "Неизвестно")
                        self.db["computers"][pc_id]["status"] = "free"
                        self.db["computers"][pc_id]["client"] = None
                        self.db["computers"][pc_id]["start_time"] = None
                        self.db["computers"][pc_id]["end_time"] = None
                        log_action("Система", f"Автоматически освобожден компьютер '{pc_id}' (время вышло, клиент '{client_name}')")
                        changed = True
                except ValueError:
                    pass
        if changed:
            save_data(self.db, DATA_FILE)
            self.build_computers_tab()

        # Запускаем проверку каждую минуту (60000 мс)
        self.root.after(60000, self.check_expired_sessions)

    def rent_pc(self, pc_id):
        rent_window = tk.Toplevel(self.root)
        rent_window.title(f"Аренда {pc_id}")
        rent_window.geometry("300x200")
        rent_window.transient(self.root)
        rent_window.grab_set()

        tk.Label(rent_window, text="Имя клиента:").pack(pady=10)
        name_entry = tk.Entry(rent_window)
        name_entry.pack(pady=0)

        tk.Label(rent_window, text="Количество часов:").pack(pady=10)
        hours_spinbox = tk.Spinbox(rent_window, from_=1, to=24, width=5)
        hours_spinbox.pack(pady=0)

        def confirm():
            client_name = name_entry.get().strip()
            if not client_name:
                messagebox.showwarning("Внимание", "Введите имя клиента!", parent=rent_window)
                return
            try:
                hours = int(hours_spinbox.get())
                if hours <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showwarning("Внимание", "Некорректное количество часов!", parent=rent_window)
                return

            start_dt = datetime.now()
            end_dt = start_dt + timedelta(hours=hours)

            self.db["computers"][pc_id]["status"] = "busy"
            self.db["computers"][pc_id]["client"] = client_name
            self.db["computers"][pc_id]["start_time"] = start_dt.strftime("%Y-%m-%d %H:%M")
            self.db["computers"][pc_id]["end_time"] = end_dt.strftime("%Y-%m-%d %H:%M")

            save_data(self.db, DATA_FILE)
            log_action(self.current_user, f"Клиент '{client_name}' посажен за '{pc_id}' на {hours} ч.")
            self.build_computers_tab()
            rent_window.destroy()

        btn_frame = tk.Frame(rent_window)
        btn_frame.pack(pady=15)
        tk.Button(btn_frame, text="Забронировать", command=confirm).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Отмена", command=rent_window.destroy).pack(side=tk.RIGHT, padx=10)

    def free_pc(self, pc_id):
        client_name = self.db["computers"][pc_id].get("client", "Неизвестно")
        self.db["computers"][pc_id]["status"] = "free"
        self.db["computers"][pc_id]["client"] = None
        self.db["computers"][pc_id]["start_time"] = None
        self.db["computers"][pc_id]["end_time"] = None
        save_data(self.db, DATA_FILE)
        log_action(self.current_user, f"Освобожден компьютер '{pc_id}' (закрыт сеанс '{client_name}')")
        self.build_computers_tab()

    def logout(self):
        log_action(self.current_user, "Выход из системы")
        self.frame.destroy()
        LoginWindow(self.root, start_app)


def start_app(current_user, user_role, db):
    AppWindow(root, current_user, user_role, db)

if __name__ == "__main__":
    init_db()

    root = tk.Tk()
    root.title("ИС GamePoint - Система учета компьютерного клуба")
    root.geometry("650x500")

    LoginWindow(root, start_app)

    root.mainloop()
