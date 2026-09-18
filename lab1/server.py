import socket
import re

sock = socket.socket()
sock.bind(("", 9999))
sock.listen(1)

conn, addr = sock.accept()
print(f"Connection from {addr}")

data = conn.recv(1024) 
print(f"Received: {data.decode()}")
conn.send("Hello from server! If you want to use 1 option write 1 if 2 option write 2".encode())

var = 0
while True:
    data = conn.recv(1024)
    if not data:
        break

    text = data.decode()
    print(f"Received: {text}")

    if var == 0:
        if text == "1":
            var = 1
            text = "First option selected."
            print(f"Sending: {text}")
            conn.send(text.encode())
            continue
        elif text == "2":
            var = 2
            text = "Second option selected."
            print(f"Sending: {text}")
            conn.send(text.encode())
            continue
        else:
            text = "Invalid option. Please send 1 or 2."
            print(f"Sending: {text}")
            conn.send(text.encode())
            continue

    if var == 1:
        text = text.replace('[', '(').replace(']', ')')
    elif var == 2:
        text =  re.sub(r' +', ' ', text)
    print(f"Sending: {text}")
    conn.send(text.encode())

conn.close()