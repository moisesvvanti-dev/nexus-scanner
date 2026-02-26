<div align="center">
  <img src="https://raw.githubusercontent.com/MatrixTM/PyRoxy/master/logo.png" alt="Logo" width="100"/>
  <h1>PentestGPT (Nexus Ultima v20)</h1>
  <p><strong>Advanced Penetration Testing & Reconnaissance Framework Powered by AI</strong></p>
  
  <p>
    <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
    <a href="https://github.com/MatrixTM/PyRoxy"><img src="https://img.shields.io/badge/Powered_by-PyRoxy-red?style=for-the-badge" alt="PyRoxy"></a>
    <a href="#"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"></a>
  </p>
</div>

---

## 📌 O que é o PentestGPT?

**PentestGPT (Nexus Ultima)** é uma ferramenta completa e automatizada de segurança ofensiva focada em *Reconhecimento (Recon)*, *Análise de Vulnerabilidades* e *Descoberta de Dados Sensíveis*. Construída puramente em Python (utilizando PySide6 para uma interface gráfica Cyberpunk imersiva), a ferramenta integra algoritmos inteligentes de verificação rigorosa (**Strict Validation**) para eliminar falsos positivos e atua com um sistema robusto de rotação de proxies (**ProxyManager**) para testes contínuos e resilientes em larga escala.

Ele combina varredura da web, scraping de JavaScript, fuzzing de parâmetros heurísticos e inteligência artificial para fornecer relatórios detalhados sobre as falhas de segurança de um alvo, tudo isso através de engenharias assíncronas super-rápidas (`aiohttp` e `qasync`).

## 🚀 Principais Funcionalidades

*   🛡️ **Smart Proxy Manager**: Rotação avançada de proxies (HTTP/SOCKS4/SOCKS5) coletados de múltiplas fontes públicas. O sistema testará conectividade (ping/latência), calculará pontuações de saúde e descartará automaticamente *dead-proxies* em *background*, garantindo que seus scans nunca sejam paralisados por IPs ruins.
*   🎯 **Strict Validation Engine**: Motor avançado de verificação *Anti-False-Positive*. O `DirectoryBruter` mapeia a variância dinâmica das páginas 404 (Soft 404s), bloqueando ruídos do servidor. O `CVEScanner` valida o tamanho do conteúdo e impede a reflexão de payloads enganosos, fornecendo apenas "Hits" 100% reais e validados.
*   🔍 **Subdomain Enumeration & Takeover**: Varredura em profundidade de transparência de certificados (`crt.sh`) aliada à checagem ativa de vulnerabilidades de sequestro de subdomínio (*Subdomain Takeover*).
*   🔑 **Sensitive Data Hunter**: Busca agressiva para encontrar e formatar painéis administrativos vazados, logs expostos, credenciais perdidas (SSH, AWS Keys, JWTs, `.env`, `.sql`). Possui verificação de métrica de entropia (Shannon Entropy) para diferenciar senhas reais de *placeholders*.
*   🕷️ **JavaScript Asset Mining**: Extração inteligente de lógica de negócios, *endpoints* de APIs escondidos (ex: `/api/v1/...`) e chaves *hardcoded* expostas em arquivos de front-end minificados `.js`.
*   🛠️ **Port Scanning & Banner Grabbing**: Identificação rápida das portas corporativas mais críticas da web, revelando serviços ativos como HTTP, HTTPS, SSH, MySQL, FTP e bancos de dados não autenticados.
*   🔥 **Heuristic Parameter Fuzzing**: Testes automatizados focados para descobrir SQLi, LFI, RCE, e XSS Refletidos diretamente dos parâmetros de URL capturados durante o recon.
*   🤖 **AI Assistant Integration**: Integração nativa no painel com capacidades LLMs avançadas (ex: Llama3 via Groq API) para analisar anomalias de código, gerar scripts personalizados de exploit e interpretar comportamentos complexos de respostas dos servidores durante o Pentest.

---

## ⚙️ Instalação Automática (Windows)

A ferramenta foi projetada para ser iniciante ou *Plug-and-Play*. Criamos um **auto-instalador em Batch** (`install.bat`) que lidará com todo o ecossistema e ambiente local para você.

### Passo a Passo:

1. Baixe os arquivos deste repositório ou clone usando o git localmente:
   ```cmd
   git clone https://github.com/moisesvvanti-dev/nexus-scanner.git
   cd nexus-scanner
   ```
2. Caso não o tenha, instale o **[Python 3.10 ou superior](https://www.python.org/downloads/)** e lembre-se de marcar a caixa de *"Add Python to PATH"* no instalador.
3. Na pasta raiz, dê um duplo clique no arquivo **`install.bat`**.
4. O instalador operará **automaticamente**:
   * Checará as dependências do Python em sua máquina.
   * Atualizará o construtor do pacote básico (`pip`).
   * Instalará perfeitamente todas as dezenas de dependências vitais de rede listadas no `requirements.txt` diretamente na sua máquina.
   * Executará downloads internos de base em background para módulos dinâmicos (como o suporte de headless browsing do *Playwright*).
5. Aguarde até ver a mensagem verde sinalizando: `"Installation Completed Successfully!"` (Pressione Enter para fechar caso pause).

---

## 💻 Como Iniciar e Usar

Uma vez que a instalação esteja concluída, seu projeto está preparado.

Para abrir a interface gráfica do scanner principal, você deve invocar o arquivo `main.py` através do Prompt de Comando diretamente na pasta raiz do PentestGPT:

#### Opção recomendada (Usando CMD):
```cmd
python main.py
```

### Usando a Ferramenta

1. **Dashboard Inicial**: O programa exibirá o painel principal guiado (UI) de comandos e estátisticas no formato "Nexus".
2. **Setup Rápido**: Insira no campo alvo sua "Target URL" (ex: `http://example.com`).
3. **Modificadores Críticos**: 
   * `Deep Scan`: Ativará o caçador Javascript e Fuzzing passivo.
   * `Bypass Mode (Proxies)`: Encaminhará requisições usando o banco super otimizado testado do `ProxyManager`.
   * *Nota*: O nível de *Strict Validation* de payloads e falsos HTTP 200 já operam por padrão na arquitetura (v20).
4. Visualize os alertas vermelhos e verdes no centro da tela com extração contínua da Inteligência!

---

## 🛠️ Tecnologias Principais e Bibliotecas

*   **Front-end GUI:** `PySide6` (Poder do Qt re-imaginado para Python) + integração assíncrona com `qasync`.
*   **Networking & Scrapers Massivos:** `aiohttp` (Motor principal do scanner), `Playwright`, `requests`, `cloudscraper`, `fake-useragent`, `nest_asyncio`.
*   **Parsing e DNS Recon:** `BeautifulSoup4`, `dnspython`, `python-whois`, `tldextract`, `yarl`.
*   **Segurança Ofensiva e Identificadores:** `PyRoxy` (Conexão e rotação de Proxies nativa customizada), `impacket` (Protocolos SMB e Auth), `wafw00f` (Bypass/Detecção de WAF).

---

## ⚠️ Disclaimer e Responsabilidade 

**Esta ferramenta ("PentestGPT") é fabricada e liberada EXCLUSIVAMENTE para fins estritos educacionais, de pesquisa acadêmica, CTFs (*Capture The Flag*) profissionais e operações validadas de Red Team/Bug Bounty.**

O uso das funções expostas, *fuzzers* e métodos de bypass sem a permissão expressa, afirmativa e escrita por parte do host detentor dos servidores e aplicações web correspondentes (o Alvo) é absolutamente **ILEGAL** de acordo com leis cibernéticas ao redor do globo.

O desenvolvedor e os contribuidores por trás das manutenções tecnológicas ligadas a este repositório abstêm-se publicamente e legalmente de **QUALQUER** responsabilidade relativa a multas, mau uso, corrupção e perdas de dados alheios e danos causados pelo uso direto ou indireto advindo dessa estrutura.

Sempre opere ética e legalmente de acordo com a premissa fundamental: *SEJA ÉTICO. OBTENHA AUTORIZAÇÃO CLARA PRIMEIRO*. 🛡️

---

<div align="center">
  <p>Construído e Arquitetado com ⚔️ por <b>[moises vianna vanti]</b></p>
</div>
