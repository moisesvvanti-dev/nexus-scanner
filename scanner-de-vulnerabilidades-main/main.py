import sys
import socket
from scanner import PortScanner

def run():
    print("-" * 30)
    print("PYTHON CYBER SCANNER v1.0")
    print("-" * 30)
    
    alvo = input("Digite o host ou IP (ex: scanme.nmap.org): ")
    
    try:
        inicial_port = int(input("Porta inicial (ex: 1): "))
        final_port = int(input("Porta final (ex: 100): "))
    except ValueError:
        print("\n[!] Erro: Por favor, insira números válidos para as portas.")
        sys.exit()
        
    try:
        
        target_ip = socket.gethostbyname(alvo)
        print(f"\n[!] Escaneando: {target_ip}")
        
        scanner = PortScanner(target_ip, inicial_port, final_port)
        
        resultados = scanner.scan_ports()
        
        print("\n" + "=" * 30)
        print("RESUMO DO SCAN:")
        for porta, banner in resultados.items():
            print(f"Porta {porta}: {banner}")
        print("=" * 30)

    except socket.gaierror:
        print("\n[!] Erro: Não foi possível resolver o endereço do host.")
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrompido pelo usuário. Saindo com segurança...")
        sys.exit()
    except Exception as e:
        print(f"\n[!] Ocorreu um erro inesperado: {e}")

if __name__ == "__main__":
    run()