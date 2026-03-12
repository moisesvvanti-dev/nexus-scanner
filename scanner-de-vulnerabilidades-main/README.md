
# 🛡️ Python Cyber Scanner

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/focus-cybersecurity-red)

O **Python Cyber Scanner** é uma ferramenta de reconhecimento de rede (recon) modular, desenvolvida para identificar portas TCP abertas e realizar a extração de banners de serviços. Ideal para estudantes de cibersegurança que desejam entender o funcionamento do protocolo TCP e a biblioteca `socket` do Python.

## ✨ Funcionalidades

- **🔍 Escaneamento Preciso:** Varredura de portas TCP utilizando o método `connect_ex` para maior estabilidade.
- **🚩 Banner Grabbing:** Tentativa de captura de cabeçalhos de serviços (SSH, HTTP, FTP, etc.) para identificação de versões.
- **🏗️ Arquitetura POO:** Código modularizado e orientado a objetos, facilitando a manutenção e expansão.
- **🛡️ Tratamento de Erros:** Gestão de exceções para interrupções forçadas (`Ctrl+C`) e falhas de resolução de DNS.

## 🛠️ Tecnologias e Bibliotecas

* **Python 3**
* **Socket:** Manipulação de conexões de rede de baixo nível.
* **Sys/OS:** Controle de interface de terminal e saída de dados.

## 🚀 Como Instalar e Usar

1. **Necessário ter o Python3 instalado**
2. **Clonar o Repositório:**

   ```bash
   git clone [https://github.com/seu-usuario/python-cyber-scanner.git](https://github.com/seu-usuario/python-cyber-scanner.git)
   cd python-cyber-scanner
   ```
3. **Executar a ferramenta:**

   ```bash
   python main.py
   ```
4. **Parâmetros:**

   - Informe o **Host** (ex: `scanme.nmap.org`) ou o **IP**.
   - Defina o **intervalo de portas** (ex: 20 a 1000).

## 📂 Estrutura do Projeto


| **Arquivo** | **Descrição**                                                   |
| ----------------- | ----------------------------------------------------------------------- |
| `main.py`       | Interface de usuário, captura de inputs e tratamento de erros globais. |
| `scanner.py`    | Classe principal com a lógica de conexão e banner grabbing.           |
| `README.md`     | Documentação do projeto.                                              |
| `LICENSE`       | Licença de uso MIT.                                                    |



## ⚠️ Aviso Legal (Disclaimer)

Esta ferramenta foi desenvolvida estritamente para  **fins educacionais**. O escaneamento de redes e sistemas sem autorização prévia é ilegal e pode ser rastreado. A desenvolvedora não se responsabiliza pelo uso indevido deste software. Utilize-o apenas em ambientes controlados ou redes autorizadas.


**Desenvolvido com ❤️ por Gabriela Dias**
