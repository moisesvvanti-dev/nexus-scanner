import socket

class PortScanner:
    def __init__(self, target, start_port, end_port):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port

    def scan_ports(self):
        found_services = {}
        
        for port in range(self.start_port, self.end_port + 1):
            the_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            the_socket.settimeout(0.7)
            
            result = the_socket.connect_ex((self.target, port))
            
            if result == 0:
                banner = "Identificador não disponível"
                try:
                    data = the_socket.recv(1024)
                    if data:
                        banner = data.decode().strip()
                except:
                    pass
                
                found_services[port] = banner
                print(f"[+] Porta {port} aberta: {banner}")
            
            else:
                print(f"[-] Porta {port} fechada")
            
            the_socket.close()
            
        return found_services