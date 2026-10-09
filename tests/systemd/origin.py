import socketserver
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data=bytearray()
        while chunk:=self.request.recv(32768):
            data.extend(chunk)
            if len(data)>16*1024*1024:return
        if data:self.request.sendall(data)
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
Server(('127.0.0.1',18081),Echo).serve_forever()
