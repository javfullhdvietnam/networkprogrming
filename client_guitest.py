"""
Media Chat Client – robust GUI version
Handles file‑transfer without connection reset by coordinating
receiver & sender via threading.Event() flags.
"""
import socket
import threading
import os
import hashlib
import queue
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from media_preview import open_media

HOST = '117.5.210.143'
PORT = 5000
RECEIVED_FOLDER = 'client_downloads'
BUF = 4096
os.makedirs(RECEIVED_FOLDER, exist_ok=True)

# ---------------- Utility ---------------- #

def sha256_checksum(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(BUF), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------------- Tk App ---------------- #

class MediaChatClient(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Media Chat Client")
        self.minsize(620, 480)
        self.protocol("WM_DELETE_WINDOW", self.on_exit)

        # net
        self.sock: socket.socket | None = None
        self.recv_q: queue.Queue[str] = queue.Queue()
        self.recv_thread: threading.Thread | None = None

        # flow‑control flags
        self.uploading = threading.Event()   # True while bytes of a file are on the wire
        self.ack_event = threading.Event()   # Signalled when server responds after upload

        self._build_widgets()
        self.after(100, self._poll_queue)
        self.after(100, self.prompt_login)

    # ---------- widgets ---------- #
    def _build_widgets(self):
        self.chat = scrolledtext.ScrolledText(self, wrap=tk.WORD, state=tk.DISABLED)
        self.chat.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, padx=4, pady=4)
        self.entry = ttk.Entry(bottom)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.bind('<Return>', lambda _: self.send_text())
        ttk.Button(bottom, text="Send", width=8, command=self.send_text).pack(side=tk.LEFT, padx=2)
        ttk.Button(bottom, text="Send File", command=self.send_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(bottom, text="Request File", command=self.request_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(bottom, text="Clear Cache", command=self.clear_cache).pack(side=tk.LEFT, padx=2)
        ttk.Button(bottom, text="Exit", command=self.on_exit).pack(side=tk.LEFT, padx=2)

    # ---------- login ---------- #
    def prompt_login(self):
        win = tk.Toplevel(self)
        win.title("Login")
        win.transient(self)
        win.grab_set()
        ttk.Label(win, text="Username:").grid(row=0, column=0, sticky='e', padx=4, pady=4)
        user_var = tk.StringVar()
        ttk.Entry(win, textvariable=user_var).grid(row=0, column=1, padx=4, pady=4)
        ttk.Label(win, text="Password:").grid(row=1, column=0, sticky='e', padx=4, pady=4)
        pass_var = tk.StringVar()
        ttk.Entry(win, textvariable=pass_var, show='*').grid(row=1, column=1, padx=4, pady=4)

        def connect():
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((HOST, PORT))
                self.sock.send(f"{user_var.get().strip()}|{pass_var.get().strip()}\n".encode())
                self._append_chat(self._recv_line())
                self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
                self.recv_thread.start()
                win.destroy()
            except Exception as e:
                messagebox.showerror("Connection error", str(e))
        ttk.Button(win, text="Connect", command=connect).grid(row=2, column=0, columnspan=2, pady=6)
        win.bind('<Return>', lambda _: connect())

    # ---------- receiver ---------- #
    def _recv_line(self) -> str:
        """Read until \n (handling server close)"""
        data = bytearray()
        while True:
            ch = self.sock.recv(1)
            if not ch:
                break
            if ch == b'\n':
                break
            data.extend(ch)
        return data.decode(errors='ignore')

    def _recv_loop(self):
        try:
            while True:
                if self.uploading.is_set():
                    time.sleep(0.05)
                    continue
                header = self._recv_line()
                if not header:
                    break
                if header.startswith("FILE_TRANSFER"):
                    _, fname, fsize = header.strip().split('|')
                    fsize = int(fsize)
                    path = os.path.join(RECEIVED_FOLDER, fname)
                    with open(path, 'wb') as f:
                        remain = fsize
                        while remain > 0:
                            chunk = self.sock.recv(min(BUF, remain))
                            if not chunk:
                                raise ConnectionError("Unexpected EOF during file recv")
                            f.write(chunk)
                            remain -= len(chunk)
                    self.recv_q.put(f"[+] File '{fname}' saved → {path}")
                    open_media(path)
                else:
                    # If upload in progress, treat first non-binary line as ack
                    if self.ack_event.is_set() is False and self.uploading.is_set():
                        self.ack_event.set()
                    self.recv_q.put(header)
        except Exception as e:
            self.recv_q.put(f"[!] Receiver error: {e}")

    # ---------- queue poll ---------- #
    def _poll_queue(self):
        while not self.recv_q.empty():
            self._append_chat(self.recv_q.get())
        self.after(80, self._poll_queue)

    # ---------- send text ---------- #
    def send_text(self):
        msg = self.entry.get().strip()
        if not msg or not self.sock:
            return
        try:
            self.sock.send(f"TEXT|{msg}\n".encode())
            self._append_chat(f"[Me] {msg}")
            self.entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send error", str(e))

    # ---------- send file (with ack waiting) ---------- #
    def send_file(self):
        if not self.sock:
            return
        path = filedialog.askopenfilename()
        if not path:
            return
        fname = os.path.basename(path)
        fsize = os.path.getsize(path)
        fhash = sha256_checksum(path)
        try:
            # prepare flags
            self.uploading.set()
            self.ack_event.clear()
            # header
            self.sock.send(f"FILE|{fname}|{fsize}|{fhash}\n".encode())
            # payload
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(BUF), b""):
                    self.sock.sendall(chunk)
            self._append_chat(f"[Me] Sent file: {fname} ({fsize} bytes). Waiting ACK…")
            # wait for server response (max 10 s)
            if not self.ack_event.wait(10):
                raise TimeoutError("No acknowledgment from server after upload")
        except Exception as e:
            messagebox.showerror("File send error", str(e))
        finally:
            self.uploading.clear()

    # ---------- request file ---------- #
    def request_file(self):
        if not self.sock:
            return
        name = simple_input(self, "Request File", "Filename to get:")
        if name:
            try:
                self.sock.send(f"GET_FILE|{name}\n".encode())
            except Exception as e:
                messagebox.showerror("Request error", str(e))

    # ---------- misc ---------- #
    def clear_cache(self):
        for f in os.listdir(RECEIVED_FOLDER):
            try:
                os.remove(os.path.join(RECEIVED_FOLDER, f))
            except Exception:
                pass
        self._append_chat("[*] Cache cleared")

    def _append_chat(self, line: str):
        self.chat.configure(state=tk.NORMAL)
        self.chat.insert(tk.END, line + "\n")
        self.chat.see(tk.END)
        self.chat.configure(state=tk.DISABLED)

    def on_exit(self):
        try:
            if self.sock:
                self.sock.close()
        finally:
            self.destroy()

# ---------- modal input helper ---------- #

def simple_input(root: tk.Tk, title: str, prompt: str):
    win = tk.Toplevel(root)
    win.title(title)
    win.transient(root)
    win.grab_set()
    ttk.Label(win, text=prompt).pack(padx=8, pady=8)
    var = tk.StringVar()
    ent = ttk.Entry(win, textvariable=var)
    ent.pack(padx=8, pady=4)
    ent.focus_set()

    def ok():
        win.destroy()
    ttk.Button(win, text="OK", command=ok).pack(pady=6)
    win.bind('<Return>', lambda _: ok())
    root.wait_window(win)
    return var.get().strip()

# ---------- main ---------- #
if __name__ == '__main__':
    app = MediaChatClient()
    app.mainloop()
