import hashlib
import json
import os
import secrets
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

APP_NAME = "Protetor de Programas"
APP_DIR = Path(os.environ.get("APPDATA", Path.home())) / "ProtetorProgramas"
CONFIG_FILE = APP_DIR / "config.json"


def hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240_000).hex()


def create_config(password: str) -> dict:
    salt = secrets.token_bytes(16).hex()
    return {
        "salt": salt,
        "password_hash": hash_password(password, salt),
        "programs": []
    }


def load_config() -> dict | None:
    if not CONFIG_FILE.exists():
        return None
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
        if not all(key in data for key in ("salt", "password_hash", "programs")):
            raise ValueError("configuração incompleta")
        return data
    except Exception as exc:
        messagebox.showerror(APP_NAME, f"Não foi possível ler a configuração:\n{exc}")
        return None


def save_config(config: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    temporary = CONFIG_FILE.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(config, file, ensure_ascii=False, indent=2)
    temporary.replace(CONFIG_FILE)


def ask_new_password(parent: tk.Misc) -> str | None:
    dialog = tk.Toplevel(parent)
    dialog.title("Criar senha")
    dialog.resizable(False, False)
    dialog.transient(parent)
    dialog.grab_set()

    result = {"value": None}
    frame = ttk.Frame(dialog, padding=16)
    frame.grid()
    ttk.Label(frame, text="Crie a senha principal do protetor:").grid(row=0, column=0, columnspan=2, pady=(0, 10))
    ttk.Label(frame, text="Senha:").grid(row=1, column=0, sticky="w", pady=4)
    password = ttk.Entry(frame, show="*", width=25)
    password.grid(row=1, column=1, pady=4)
    ttk.Label(frame, text="Confirmar:").grid(row=2, column=0, sticky="w", pady=4)
    confirmation = ttk.Entry(frame, show="*", width=25)
    confirmation.grid(row=2, column=1, pady=4)

    def confirm():
        first = password.get()
        second = confirmation.get()
        if len(first) < 4:
            messagebox.showwarning(APP_NAME, "A senha deve ter pelo menos 4 caracteres.", parent=dialog)
        elif first != second:
            messagebox.showwarning(APP_NAME, "As senhas não coincidem.", parent=dialog)
        else:
            result["value"] = first
            dialog.destroy()

    ttk.Button(frame, text="Criar senha", command=confirm).grid(row=3, column=0, columnspan=2, pady=(12, 0))
    password.focus_set()
    dialog.bind("<Return>", lambda _event: confirm())
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    parent.wait_window(dialog)
    return result["value"]


class ProtectedProgramsApp:
    def __init__(self, root: tk.Tk, config: dict):
        self.root = root
        self.config = config
        self.root.title(APP_NAME)
        self.root.geometry("700x430")
        self.root.minsize(560, 330)

        style = ttk.Style()
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass

        self.build_ui()
        self.refresh_list()

    def build_ui(self):
        main = ttk.Frame(self.root, padding=16)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text="Programas protegidos", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(
            main,
            text="Cadastre atalhos ou arquivos .exe. Para abrir, selecione um item e informe a senha.",
        ).pack(anchor="w", pady=(4, 12))

        list_frame = ttk.Frame(main)
        list_frame.pack(fill="both", expand=True)
        self.program_list = tk.Listbox(list_frame, activestyle="none", font=("Segoe UI", 10), selectmode=tk.SINGLE)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.program_list.yview)
        self.program_list.configure(yscrollcommand=scrollbar.set)
        self.program_list.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.program_list.bind("<Double-Button-1>", lambda _event: self.launch_selected())

        buttons = ttk.Frame(main)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Adicionar programa", command=self.add_program).pack(side="left")
        ttk.Button(buttons, text="Remover selecionado", command=self.remove_program).pack(side="left", padx=8)
        ttk.Button(buttons, text="Abrir com senha", command=self.launch_selected).pack(side="right")

        ttk.Separator(main).pack(fill="x", pady=14)
        bottom = ttk.Frame(main)
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Alterar senha", command=self.change_password).pack(side="left")
        ttk.Label(bottom, text=f"Configuração: {CONFIG_FILE}", foreground="#666666").pack(side="right")

    def authenticate(self) -> bool:
        password = simpledialog.askstring(APP_NAME, "Digite a senha principal:", show="*", parent=self.root)
        if password is None:
            return False
        expected = self.config["password_hash"]
        actual = hash_password(password, self.config["salt"])
        if secrets.compare_digest(actual, expected):
            return True
        messagebox.showerror(APP_NAME, "Senha incorreta.", parent=self.root)
        return False

    def refresh_list(self):
        self.program_list.delete(0, tk.END)
        for item in self.config["programs"]:
            self.program_list.insert(tk.END, f"{item['name']}  —  {item['path']}")

    def add_program(self):
        if not self.authenticate():
            return
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Selecione o programa",
            filetypes=[("Programas Windows", "*.exe"), ("Todos os arquivos", "*.*")],
        )
        if not path:
            return
        name = Path(path).stem
        self.config["programs"].append({"name": name, "path": path})
        save_config(self.config)
        self.refresh_list()

    def remove_program(self):
        selection = self.program_list.curselection()
        if not selection:
            messagebox.showinfo(APP_NAME, "Selecione um programa para remover.", parent=self.root)
            return
        if not self.authenticate():
            return
        index = selection[0]
        item = self.config["programs"][index]
        if messagebox.askyesno(APP_NAME, f"Remover '{item['name']}'?", parent=self.root):
            self.config["programs"].pop(index)
            save_config(self.config)
            self.refresh_list()

    def launch_selected(self):
        selection = self.program_list.curselection()
        if not selection:
            messagebox.showinfo(APP_NAME, "Selecione um programa para abrir.", parent=self.root)
            return
        if not self.authenticate():
            return
        item = self.config["programs"][selection[0]]
        try:
            if not Path(item["path"]).exists():
                raise FileNotFoundError(item["path"])
            subprocess.Popen([item["path"]], cwd=str(Path(item["path"]).parent))
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Não foi possível abrir o programa:\n{exc}", parent=self.root)

    def change_password(self):
        if not self.authenticate():
            return
        new_password = ask_new_password(self.root)
        if new_password:
            new_config = create_config(new_password)
            new_config["programs"] = self.config["programs"]
            self.config = new_config
            save_config(self.config)
            messagebox.showinfo(APP_NAME, "Senha alterada com sucesso.", parent=self.root)


def main():
    root = tk.Tk()
    root.title(APP_NAME)
    root.geometry("700x430")
    root.minsize(560, 330)
    root.update_idletasks()
    config = load_config()
    if config is None:
        password = ask_new_password(root)
        if not password:
            root.destroy()
            return
        config = create_config(password)
        save_config(config)
    ProtectedProgramsApp(root, config)
    root.mainloop()


if __name__ == "__main__":
    main()
