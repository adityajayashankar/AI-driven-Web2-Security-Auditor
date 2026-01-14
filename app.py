import ssl
import socket

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # ❌ weak / deprecated TLS

with socket.create_connection(("example.com", 443)) as sock:
    with context.wrap_socket(sock, server_hostname="example.com") as ssock:
        print(ssock.version())
