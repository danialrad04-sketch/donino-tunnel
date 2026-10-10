import socketserver
import threading
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data=bytearray()
        while chunk:=self.request.recv(32768):
            data.extend(chunk)
            if len(data)>16*1024*1024:return
        if data:self.request.sendall(data)
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
class StreamEcho(socketserver.BaseRequestHandler):
    def handle(self):
        while chunk:=self.request.recv(32768):self.request.sendall(chunk)
class DatagramEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data,socket=self.request;socket.sendto(data,self.client_address)
for address,server,handler in [(18082,socketserver.ThreadingUDPServer,DatagramEcho),(18083,Server,StreamEcho)]:
    threading.Thread(target=server(('127.0.0.1',address),handler).serve_forever,daemon=True).start()
Server(('127.0.0.1',18081),Echo).serve_forever()
