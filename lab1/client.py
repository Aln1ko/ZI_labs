import socket

sock = socket.socket()
sock.connect(("localhost", 9999))

hello = "Hello from client!"

with open("output.txt", "w", encoding="utf-8") as f:
    f.write("client -> " + hello + "\n")
sock.send(hello.encode())

data = sock.recv(1024)
print(data.decode())

with open("output.txt", "a", encoding="utf-8") as f:
    f.write("server -> " + data.decode() + "\n")


while True:
    message = input("Enter message to send or quit to exit: ") 
    if message.lower() == "quit":
        with open("output.txt", "a", encoding="utf-8") as f:
                f.write("client -> " + message + "\n")
        break
    elif message.lower() == "file":
        try:
            with open("input.txt", "r", encoding="utf-8") as f:
                message = f.read()
        except FileNotFoundError:
            print("File not found.")
            continue
    with open("output.txt", "a", encoding="utf-8") as f:
            f.write("client -> " + message + "\n")

    sock.send(message.encode())
    data = sock.recv(1024)
    print(f"Received: {data.decode()}")

    with open("output.txt", "a", encoding="utf-8") as f:
        f.write("server -> " + data.decode() + "\n")

sock.close()

