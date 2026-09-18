import socket
import json
import os
import random

port = 7700
DB_FILE = "database.json"
DOCS_DIR = "Server_docs"
PROMPT = "Enter message to send or quit to exit or help for assistance"
shift = 7 
p = 1559

def is_primitive_root(g, p):
    # Розкладаємо p - 1 на прості множники
    n = p - 1
    factors = set()
    d = 2
    temp = n
    while d * d <= temp:
        if temp % d == 0:
            factors.add(d)
            while temp % d == 0:
                temp //= d
        d += 1
    if temp > 1:
        factors.add(temp)

    # Перевіряємо умову для кожного множника
    for q in factors:
        if pow(g, n // q, p) == 1:
            return False
    return True

def find_g():
    for g in range(2, p):
        if is_primitive_root(g, p):
            print(f"p = {p}, генератор g = {g}")
            return g 

def handshake(conn,g,p):
    data = conn.recv(1024).decode('utf-8')
    public_a = int(data)

    b = random.randint(100,5000)
    public_b = pow(g,b,p)
    conn.send(f"{public_b}".encode('utf-8'))

    shared_key = pow(public_a,b,p)
    return shared_key


def encrypt(data:bytes,shift:int,key:int):
    k_byte = key%256
    return bytes(((b^k_byte)+shift)%256 for b in data)

def decrypt(data: bytes, shift: int, key: int):
    k_byte = key % 256
    return bytes(((b - shift) % 256) ^ k_byte for b in data)


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc  # повертає 16-бітне ціле число (0..65535)

def hash_password(password: str) -> str:
    # Отримуємо 16-бітний хеш і записуємо як шістнадцятковий рядок, наприклад "a1b2"
    return f"{crc16(password.encode('utf-8')):04x}"

def send_secure(conn, message_text: str,key):
    raw_data = message_text.encode('utf-8')

    checksum = crc16(raw_data)               # рахуємо 16-бітний CRC
    encrypted = encrypt(raw_data, shift,key)    # шифруємо зсувом на 7
    
    # Пакуємо: 2 байти CRC + зашифровані байти
    crc_bytes = checksum.to_bytes(2, byteorder='big')
    packet = crc_bytes + encrypted
    conn.send(packet)
    log_server("server -> " + message_text)

def recv_secure(conn,key) -> str | None:
    try:
        packet = conn.recv(4096)
    except ConnectionResetError:
        return None
    
    if not packet or len(packet) < 2:
        return None
    
    received_crc = int.from_bytes( packet[:2], byteorder='big')
    encrypted_payload = packet[2:]
    
    decrypted_bytes = decrypt(encrypted_payload, shift,key)
    
    # Перевіряємо цілісність
    if crc16(decrypted_bytes) != received_crc:
        raise ValueError("CRC помилка: дані пошкоджено або підроблено!")

    text = decrypted_bytes.decode('utf-8')
    log_server("client -> " + text)
    return text

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        return {
            "ADMIN": {
                "password_hash": "5bce", 
                "is_blocked": False,
                "must_change_password": False
            }
        }

def save_db(data):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def log_server(msg: str):
    with open("server_log.txt", "a", encoding="utf-8") as f:
        f.write(f"{msg}\n")

def wait_client():      
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("", port))
    data, (client_ip, client_port) = udp_sock.recvfrom(1024)
    log_server("client -> " + data.decode())

    if data.decode() == "DISCOVER":
        udp_sock.sendto(b"RESPONSE", (client_ip, client_port))
        log_server("server -> RESPONSE")
    udp_sock.close()

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.bind(("", port))
    tcp_sock.listen(1)

    conn, addr = tcp_sock.accept()
    print(f"TCP connection from {addr}")
    log_server("server -> " + f"TCP connection from {addr}")

    g = find_g()
    conn.send(f"{p}:{g}".encode("utf-8"))
    key = handshake(conn,g,p)

    return tcp_sock, conn, addr,key

def authenticate_user(conn, db,key):
    send_secure(conn,"Before start you need to authenticate, please enter your username",key)
    authenticated = False

    while True:
        username = recv_secure(conn,key)

        if username == "quit":
            send_secure(conn,"Goodbye!",key)
            return None,False

        if username in db:
            if db[username]["is_blocked"]:
                send_secure(conn,"Your account is blocked. Connection will be closed.",key)
                return None,False
            break
        else:
            send_secure(conn,"Invalid username. Please try again",key)

    wrong_pas_count = 0
    send_secure(conn,"OK. \nPlease enter your password",key)
    
    while wrong_pas_count < 3:
        raw_pass = recv_secure(conn,key)
        if raw_pass is None:
            return None,False # Клієнт відключився, просто перериваємо обробку

        password = hash_password(raw_pass)
        
        if raw_pass == "quit":
            send_secure(conn,"Goodbye!",key)
            return None,False

        if password != db[username]["password_hash"]:
            wrong_pas_count += 1
            if wrong_pas_count >= 3:
                send_secure(conn,"Too many failed attempts. Connection will be closed.",key)
                db[username]["is_blocked"] = True
                save_db(db)
                break
            else:
                send_secure(conn,"Invalid password. Please try again",key)
                continue

        if password == db[username]["password_hash"]:
            authenticated = True
            break

    if not authenticated:
        return None,False

    password_changed = False
    
    if db[username]["must_change_password"]:
        send_secure(conn,"You must change your password. Please enter a new password",key)
       
        while True:
            raw_pass = recv_secure(conn,key)
            if raw_pass is None:
                return  # Клієнт відключився, просто перериваємо обробку
    
            pas = hash_password(raw_pass)

            if raw_pass  == "quit":
                send_secure(conn,"Goodbye!",key)
                return None,False
            
            if pas == db[username]["password_hash"]:
                send_secure(conn,"New password cannot be the same as the old one. Please try again",key)
                continue

            send_secure(conn,"Please enter password one more time",key)
            new_pass = recv_secure(conn,key)

            if pas != hash_password(new_pass):
                send_secure(conn,"Passwords do not match. Please try again",key)
                continue
            db[username]["password_hash"] = pas
            db[username]["must_change_password"] = False
            save_db(db)
            password_changed = True
            break

    return username, password_changed if authenticated else None

help_text_admin = (
    "--- ДОВІДКА ---\n"
    "Автор: Коваленко О. М.\n"
    "Завдання: Лабораторна робота №2. Віддалений доступ до захищених даних.\n"
    "Варіант: Шифр зсуву на 7 символів, хеш CRC16.\n"
    "Команди:\n"
    "1. block <user> - Заблокувати користувача\n"
    "2. unblock <user> - Розблокувати користувача\n"
    "3. create <user>  - Додати нового користувача\n"
    "4. change password - Змінити пароль\n"
    "5. quit - Завершити сесію\n"
    "6. help - Показати довідку\n"
    "7. get doc - Отримати захищений документ\n"
) 

help_text_user = (
    "--- ДОВІДКА ---\n"
    "Автор: Коваленко О. М.\n"
    "Завдання: Лабораторна робота №2. Віддалений доступ до захищених даних.\n"
    "Варіант: Шифр зсуву на 7 символів, хеш CRC16.\n"
    "Команди:\n"
    "1. change password - Змінити пароль\n"
    "2. quit - Завершити сесію\n"
    "3. help - Показати довідку\n"
    "4. get doc - Отримати захищений документ\n"
) 

def set_user_block_status(conn, db, parts, block_state: bool,key):
    action_str = "block" if block_state else "unblock"
    done_str = "blocked" if block_state else "unblocked"

    if len(parts) < 2:
        msg = f"Please specify a username to {action_str}."
    else:
        target_user = parts[1]
        if target_user not in db:
            msg = f"User {target_user} does not exist."
        elif target_user == "ADMIN":
            msg = f"You cannot {action_str} the ADMIN user."
        elif db[target_user]["is_blocked"] == block_state:
            msg = f"User {target_user} is already {done_str}."
        else:
            db[target_user]["is_blocked"] = block_state
            save_db(db)
            msg = f"User {target_user} has been {done_str}."
    all_message = msg + "\n" + PROMPT
    send_secure(conn,all_message,key)

def create_user(conn, db, parts,key):
    if len(parts) < 2:
        send_secure(conn,f"Please specify a username to create a new user.\n{PROMPT}",key)
    else:
        username_to_create = parts[1]
        if username_to_create in db:
            send_secure(conn,f"User {username_to_create} already exists\n{PROMPT}",key)
        else:
            send_secure(conn,"Please enter a password to create a new user",key)

            raw_pass = recv_secure(conn,key)
            if raw_pass is None:
                return  # Клієнт відключився, просто перериваємо обробку

            password_input = hash_password(raw_pass)

            db[username_to_create] = {
                "password_hash": password_input,
                "is_blocked": False,
                "must_change_password": True
            }
            save_db(db)
            send_secure(conn,f"User {username_to_create} has been created.\n{PROMPT}",key)

def change_password(conn, db, authenticated_user,key):
    send_secure(conn,"Please enter your old password",key)
    raw_pass = recv_secure(conn,key)
    if raw_pass is None:
        return  # Клієнт відключився, просто перериваємо обробку
    old_password = hash_password(raw_pass)

    if  old_password != db[authenticated_user]["password_hash"]:
        send_secure(conn,f"Old password is incorrect.\n{PROMPT}",key)
    else:
        send_secure(conn,"Please enter your new password",key)
        raw_pass = recv_secure(conn,key)
        if raw_pass is None:
            return  # Клієнт відключився, просто перериваємо обробку
        new_password = hash_password(raw_pass)

        if new_password == db[authenticated_user]["password_hash"]:
            send_secure(conn,f"New password cannot be the same as the old one.\n{PROMPT}",key)
            return 
        else:
            send_secure(conn,f"Please enter your new password one more time",key)
            raw_pass = recv_secure(conn,key)
            if raw_pass is None:
                return 
            new_password_confirm = hash_password(raw_pass)

            if new_password_confirm !=  new_password:
                send_secure(conn,f"Passwords do not match.\n{PROMPT}",key)
            else:
                db[authenticated_user]["password_hash"] =  new_password
                save_db(db)
                send_secure(conn,f"Password changed successfully.\n{PROMPT}",key)

def get_doc(conn,parts,key):
    if len(parts) < 2:
        send_secure(conn,"Please specify the document name.\n{PROMPT}",key)
    else:
        doc_name = parts[1]
        doc_path = os.path.join(DOCS_DIR, os.path.basename(doc_name))
        if not os.path.exists(doc_path):
            send_secure(conn,f"Document {doc_name} does not exist.\n{PROMPT}",key)
        else:
            with open(doc_path, "r", encoding="utf-8") as f:
                content = f.read()
            send_secure(conn, (content + f"\n{PROMPT}"),key)

def admin_working(text, conn, db, authenticated_user,key):
    parts = text.strip().split()
    if not parts:
            return False
    
    command = parts[0].lower()  # перше слово — завжди команда
    
    if command == "help":
        full_response = help_text_admin + PROMPT
        send_secure(conn,full_response,key)
        return False
    elif command == "block":
        set_user_block_status(conn, db, parts, block_state=True,key = key)
        return False
    elif command == "unblock":
        set_user_block_status(conn, db, parts, block_state=False,key = key)
        return False   
    elif command == "create":
        create_user(conn, db, parts,key)
        return False
    elif text.lower() == "change password":
        change_password(conn, db, authenticated_user,key)
        return False
    elif command.lower() == "get":
        get_doc(conn, parts,key)
        return False
    elif command == "quit":
        send_secure(conn,"Goodbye!",key)
        return True
    else:
        send_secure(conn,"Unknown command. Type 'help' for assistance.",key)

def user_working(text, conn, db, authenticated_user,key):
    parts = text.strip().split()
    if not parts:
        return False
    command = parts[0].lower()  # перше слово — завжди команда

    if command == "help":
        full_response = help_text_user + PROMPT
        send_secure(conn,full_response,key)
        return False
    elif text.lower() == "change password":
        change_password(conn, db, authenticated_user,key)
        return False
    elif command.lower() == "get":
        get_doc(conn, parts,key)
        return False
    elif command == "quit":
        send_secure(conn,"Goodbye!",key)
        return True
    else:
        send_secure(conn,"Unknown command. Type 'help' for assistance.")


def handle_client(conn, addr,db,key): 
    authenticated_user,password_changed = authenticate_user(conn, db,key)
    
    if authenticated_user is not None:    
        if password_changed:
            welcome_msg = f"Password changed successfully.\nAuthentication successful.\n{PROMPT} "
        else:
            welcome_msg = f"Authentication successful.\n{PROMPT}"
        send_secure(conn,welcome_msg,key)

        while True:
            text  = recv_secure(conn,key)
            if  text == None:
                print(f"Client {addr} disconnected.")
                log_server("server -> " + f"Client {addr} disconnected.")
                break

            if authenticated_user == "ADMIN":                
                should_quit = admin_working(text,conn,db,authenticated_user,key)

            else:
                should_quit = user_working(text,conn,db,authenticated_user,key)
            
            if should_quit:
                break


def start_server():
    db = load_db()
    print("Server started. Waiting for clients...")
    with open("server_log.txt", "w", encoding="utf-8") as f:
        f.write("Server started. Waiting for clients...\n")

    tcp_sock, conn, addr,key = wait_client()
    handle_client(conn, addr, db,key)
    tcp_sock.close()

if __name__ == "__main__":
    start_server()

