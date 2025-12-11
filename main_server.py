import http.server
import ssl
from handler import *

class MyHandler(http.server.BaseHTTPRequestHandler):

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()

        print("\n[+] New message received:")
        # handle incoming request
        
        res = handle_req(body)

        response_body = b"res:" + str(res[1]).encode()
        self.send_response(res[0])
        self.send_header('Content-Length', str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def do_GET(self):
        print(f"[+] GET request from {self.client_address}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"HTTPS server is running")

server_address = ("0.0.0.0", 4443)
httpd = http.server.HTTPServer(server_address, MyHandler)

# ✅ NEW CORRECT WAY (SSLContext)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("✅ Main server running on https://127.0.0.1:4443")
httpd.serve_forever()
