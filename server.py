# server.py
import socket
import threading
import os
import hashlib

HOST = '117.5.210.143'
PORT = 5000
clients = []
MEDIA_FOLDER = 'received_media'
USER_DB = 'user_credentials.txt'
LOG_FILE = 'message_history.txt'
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = ['.jpg', '.png', '.gif', '.mp3', '.wav', '.txt', '.pdf']

os.makedirs(MEDIA_FOLDER, exist_ok=True)
open(USER_DB, 'a').close()
open(LOG_FILE, 'a').close()

def sha256_checksum(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def authenticate_user(conn):
    data = conn.recv(1024).decode().strip()
    if '|' not in data:
        conn.send(b"ERROR|Invalid login format. Use username|password\n")
        return None
    username, password = data.split('|', 1)
    hashed = hashlib.sha256(password.encode()).hexdigest()

    with open(USER_DB, 'r') as f:
        for line in f:
            stored_user, stored_hash = line.strip().split('|')
            if stored_user == username and stored_hash == hashed:
                conn.send(b"OK|Login successful\n")
                return username

    with open(USER_DB, 'a') as f:
        f.write(f"{username}|{hashed}\n")
    conn.send(b"OK|New user registered\n")
    return username

def log_message(msg):
    with open(LOG_FILE, 'a') as log:
        log.write(msg + '\n')

def broadcast(message, source_conn=None):
    for client in clients:
        if client != source_conn:
            try:
                client.send((message + '\n').encode())
            except:
                clients.remove(client)

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    username = authenticate_user(conn)
    if not username:
        conn.close()
        return

    conn.send(f"INFO|Welcome {username}!\n".encode())

    while True:
        try:
            header = conn.recv(1024).decode()
            if not header:
                break
            parts = header.strip().split('|')

            if parts[0] == 'TEXT':
                msg = f"{username}: {parts[1]}"
                log_message(msg)
                broadcast(f"TEXT|{msg}", conn)

            elif parts[0] == 'FILE':
                filename, size, expected_hash = parts[1], int(parts[2]), parts[3]
                ext = os.path.splitext(filename)[1].lower()

                if size > MAX_FILE_SIZE:
                    conn.send(b"ERROR|File too large\n")
                    continue
                if ext not in ALLOWED_EXTENSIONS:
                    conn.send(b"ERROR|Unsupported file type\n")
                    continue

                filepath = os.path.join(MEDIA_FOLDER, filename)
                with open(filepath, 'wb') as f:
                    remaining = size
                    while remaining > 0:
                        data = conn.recv(min(1024, remaining))
                        if not data:
                            break
                        f.write(data)
                        remaining -= len(data)

                actual_hash = sha256_checksum(filepath)
                if actual_hash != expected_hash:
                    conn.send(b"ERROR|File corrupted\n")
                    os.remove(filepath)
                    continue
                
                # Flush any accidental leftover command part after file transfer
                try:
                    leftover = conn.recv(1, socket.MSG_PEEK)
                    if leftover == b'\n':
                        conn.recv(1)  # consume it
                except:
                    pass


                conn.send(b"OK|File received successfully\n")
                broadcast(f"NOTIFY|{username} shared file: {filename}", conn)

            elif parts[0] == 'GET_FILE':
                filename = parts[1]
                filepath = os.path.join(MEDIA_FOLDER, filename)
                if os.path.isfile(filepath):
                    filesize = os.path.getsize(filepath)
                    conn.send(f"FILE_TRANSFER|{filename}|{filesize}\n".encode())
                    with open(filepath, 'rb') as f:
                        while True:
                            data = f.read(1024)
                            if not data:
                                break
                            conn.send(data)
                else:
                    conn.send(b"ERROR|Requested file not found\n")
        except Exception as e:
            print(f"[!] Error handling {addr}: {e}")
            break

    print(f"[-] {addr} disconnected")
    if conn in clients:
        clients.remove(conn)
    conn.close()

# Start server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"[*] Server listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        clients.append(conn)
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
