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

arr = ["123","56","789","777"]
# for i in range(1,2):
#     print(i)

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

p = 1559

def find_g():
    for g in range(2, p):
        if is_primitive_root(g, p):
            print(f"p = {p}, генератор g = {g}")
            return g 
g = find_g()
print(g)

import random

def handshake(sock):
    a = random.randint(100,500)
    public_a = pow(g,a,p)
    sock.send(f"{public_a}".encode('utf-8'))

    data = sock.recv(1024).decode('utf-8')
    public_b = int(data)

    shared_key = pow(public_b,a,p)
    return shared_key
