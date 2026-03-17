from flask import Flask, request
import subprocess
import base64
import os
import sys

app = Flask(__name__)

@app.route('/exec')
def execute_command():
    # Recebe o comando do botão do arquivo .md
    cmd_encoded = request.args.get('cmd')
    if not cmd_encoded:
        return "<h1>Erro: Nenhum comando fornecido, Excelentíssimo!</h1>", 400
        
    try:
        comando = base64.b64decode(cmd_encoded).decode('utf-8')
        print(f"[!] Ordem do Governador recebida: {comando}")
        
        # No Windows, usamos cmd.exe /k para manter o terminal aberto após o comando
        # shell=True não é necessário aqui pois estamos chamando cmd.exe diretamente
        subprocess.Popen(['cmd.exe', '/c', 'start', 'cmd.exe', '/k', comando])
        
        return "<h1>Comando Enviado ao Terminal, Excelentíssimo!</h1>"
    except Exception as e:
        return f"<h1>Erro ao processar ordem: {str(e)}</h1>", 500

def run_backend(port=5000):
    print(f"[*] Iniciando Backend do Governador na porta {port}...")
    app.run(port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    run_backend()
