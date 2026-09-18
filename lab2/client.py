import socket
import sys
import random

shift = 7

def encrypt(data:bytes,shift:int,key:int):
    k_byte = key%256
    return bytes(((b^k_byte)+shift)%256 for b in data)

def decrypt(data: bytes, shift: int, key: int):
    k_byte = key % 256
    return bytes(((b - shift) % 256) ^ k_byte for b in data)

def handshake(sock,p,g):
    a = random.randint(100,500)
    public_a = pow(g,a,p)
    sock.send(f"{public_a}".encode('utf-8'))

    data = sock.recv(1024).decode('utf-8')
    public_b = int(data)

    shared_key = pow(public_b,a,p)
    return shared_key

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

def send_secure(sock, message_text: str,key):
    raw_data = message_text.encode('utf-8')
    checksum = crc16(raw_data)               # рахуємо 16-бітний CRC
    encrypted = encrypt(raw_data, shift,key)    # шифруємо зсувом на 7
    
    # Пакуємо: 2 байти CRC + зашифровані байти
    crc_bytes = checksum.to_bytes(2, byteorder='big')
    packet = crc_bytes + encrypted
    sock.send(packet)

def recv_secure(conn,key) -> str | None:
    try:
        packet = conn.recv(4096)
    except ConnectionResetError:
        raise ConnectionError("Сервер розірвав з'єднання.")
    
    if not packet or len(packet) < 2:
        raise ConnectionError("Сервер розірвав з'єднання.")
    
    received_crc = int.from_bytes( packet[:2], byteorder='big')
    encrypted_payload = packet[2:]
    
    decrypted_bytes = decrypt(encrypted_payload, shift,key)
    
    # Перевіряємо цілісність
    if crc16(decrypted_bytes) != received_crc:
        raise ValueError("CRC помилка: дані пошкоджено або підроблено!")

    text = decrypted_bytes.decode('utf-8')
    return text


def input_masked(prompt=""):
    print(prompt, end="", flush=True)
    password = ""
    
    if sys.platform == "win32":
        import msvcrt
        while True:
            ch = msvcrt.getch()
            if ch in (b"\r", b"\n"):  # Натиснуто Enter
                print()
                break
            elif ch == b"\x08":       # Backspace
                if len(password) > 0:
                    password = password[:-1]
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            elif ch == b"\x03":       # Ctrl+C
                raise KeyboardInterrupt
            else:
                try:
                    char = ch.decode("utf-8")
                    password += char
                    sys.stdout.write("*")
                    sys.stdout.flush()
                except UnicodeDecodeError:
                    pass
    return password

port = 7700

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

udp_sock.sendto(b"DISCOVER", ("255.255.255.255", 7700))
data, (server_ip, server_port) = udp_sock.recvfrom(1024)
udp_sock.close()

print(f"Сервер знайдено на IP: {server_ip}")
with open("client_log.txt", "w", encoding="utf-8") as f:
    f.write("client -> " + f"Сервер знайдено на IP: {server_ip} on port {server_port}" + "\n")

tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sock.connect((server_ip, server_port))

server_msg = tcp_sock.recv(1024).decode("utf-8")

p_str,g_str = server_msg.split(":")
p,g = int(p_str),int(g_str)
key = handshake(tcp_sock,p,g)

server_msg = recv_secure(tcp_sock,key)
# print(server_msg)

while True:  
    with open("client_log.txt", "a", encoding="utf-8") as f:
        f.write("server -> " + server_msg + "\n")
    if "Connection will be closed" in server_msg or "Goodbye!" in server_msg:
        print(server_msg)
        break

    # Розбиваємо повідомлення від сервера на рядки і беремо останній непорожній
    lines = [line.strip() for line in server_msg.splitlines() if line.strip()]
    last_line = lines[-1].lower() if lines else ""

    # Перевіряємо, чи саме останній рядок є прямим запитом введення пароля:
    is_password_prompt = "password" in last_line and any(
    w in last_line for w in ("enter", "confirm", "new", "old", "invalid", "match","again"))
    while True:
        if is_password_prompt:
            message = input_masked(f"{server_msg}: ")
        else:
            message = input(f"{server_msg}: ")
        if message:
            break

    with open("client_log.txt", "a", encoding="utf-8") as f:
        f.write("client -> " + message + "\n")

    send_secure(tcp_sock,message,key)
    server_msg = recv_secure(tcp_sock,key)
    if not server_msg:
        print("З'єднання з сервером втрачено.")
        break

tcp_sock.close()

