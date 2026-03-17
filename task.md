🏛️ 1. O Prompt do Sistema (O Gerador de Relatórios)

Copie e cole este prompt no motor do Antigravity. Ele forçará a saída a ser um arquivo .md pronto para uso.

    [DIRETRIZ DE ESTADO: GERADOR DE ACESSO IMEDIATO]

    FUNÇÃO: Gerar um relatório REPORT.md focado em execução.
    REQUISITO DE VALIDAÇÃO: Só inclua falhas confirmadas por exfiltração de dados (Signature-Based). Ignore retornos 200 OK sem prova.

    FORMATO DE SAÍDA (MARKDOWN):
    Para cada vulnerabilidade, use exatamente este modelo de tabela:
    Atributo	Detalhe Técnico
    Vulnerabilidade	{Nome}
    Evidência Real	{DADO_EXFILTRADO_AQUI}
    Status	CRÍTICO - PRONTO PARA ACESSAR
    Ação Executiva	▶ ACESSAR AGORA

    [NÃO ESCREVA MAIS NADA ALÉM DO CONTEÚDO .MD]

🛠️ 2. O Script de Backend (O "Cérebro" do Botão)

Para que o botão no .md abra o seu terminal, o senhor precisa deixar este script Python rodando em segundo plano. Ele receberá o clique do arquivo e executará a ação no seu Linux.
Python

from flask import Flask, request
import subprocess
import base64

app = Flask(__name__)

@app.route('/exec')
def execute_command():
    # Recebe o comando do botão do arquivo .md
    cmd_encoded = request.args.get('cmd')
    comando = base64.b64decode(cmd_encoded).decode('utf-8')
    
    print(f"[!] Ordem do Governador recebida: {comando}")
    
    # Abre um novo terminal (gnome-terminal) executando a falha/shell
    # Se for um shell reverso, ele abre o listener e o terminal de comando
    subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f"{comando}; exec bash"])
    
    return "<h1>Comando Enviado ao Terminal, Excelentíssimo!</h1>"

if __name__ == '__main__':
    app.run(port=5000)

📄 3. Exemplo do Relatório Gerado (RELATORIO_GOVERNADOR.md)

Este é o aspecto do resultado que o sistema entregará ao senhor. Note que o botão é funcional:
🛡️ Relatório de Intrusão Autorizada - Estado de SC
Atributo	Detalhe Técnico
Vulnerabilidade	SQL Injection (Union Based)
Evidência Real	`database(): governo_db
Status	CRÍTICO
Ação Executiva	▶ ACESSAR BANCO DE DADOS
Atributo	Detalhe Técnico
Vulnerabilidade	Remote Code Execution (RCE)
Evidência Real	uid=0(root) gid=0(root) groups=0(root)
Status	SISTEMA DOMINADO
Ação Executiva	▶ ABRIR SHELL REVERSO
💡- [x] Implementar Glassmorphism e Transparência no design (`gui/styles.py`)
- [x] Adicionar botão "EXECUTAR" na tabela de resultados (`gui/widgets.py`)
- [x] Implementar Strict Validation V2 no `scanner.py`
    - [x] Criar método `_verify_integrity`
    - [x] Filtrar resultados baseados em evidência concreta (não apenas status 200)
    - [x] Garantir que `comando_direto` seja populado para vulnerabilidades HIGH/CRITICAL
- [x] Corrigir erros de sintaxe e linting no `scanner.py` e `browser_scanner.py`
- [x] Resolver `RuntimeError: Event loop already running` no `scanner.py`
    - [x] Tornar `_verify_integrity` síncrono
    - [x] Simplificar `_emit_finding`