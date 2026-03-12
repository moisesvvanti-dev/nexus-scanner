<div align="center">
  <img src="https://raw.githubusercontent.com/MatrixTM/PyRoxy/master/logo.png" alt="PentestGPT Logo" width="120" style="margin-bottom: 20px;"/>
  <h1 style="color: #00ffcc; text-shadow: 0 0 10px #00ffcc;">PentestGPT — Nexus Ultima v21.0</h1>
  <p><strong>🔥 O Ecossistema Definitivo de Segurança Ofensiva & Reconhecimento Guiado por Inteligência Artificial 🔥</strong></p>
  
  <p>
    <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10+-1f425f.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
    <a href="https://github.com/MatrixTM/PyRoxy"><img src="https://img.shields.io/badge/Powered_by-PyRoxy-ff0055?style=for-the-badge" alt="PyRoxy"></a>
    <img src="https://img.shields.io/badge/Status-Active_Development-00ffcc?style=for-the-badge" alt="Status">
    <a href="#aviso-legal-e-responsabilidades-️"><img src="https://img.shields.io/badge/Usage-Red_Team_Only-ff2a2a?style=for-the-badge" alt="Red Team"></a>
  </p>
</div>

<br>

> *PentestGPT não é apenas um scanner de vulnerabilidades convencional. É uma Suíte Tática Militar de Auditoria Cibernética construída em Python. Nós juntamos scraping assíncrono brutal (`aiohttp`), evasão de firewalls empresariais avançados (WAF Evasion) e a criatividade analítica de modelos LLM (Groq & Llama3) para caçar, documentar e demonstrar vulnerabilidades mortais em ambientes web massivos com tolerância zero a falsos positivos.*

---

## 📌 Arquitetura do Sistema

O **PentestGPT (Nexus Ultima)** funciona como um organismo ofensivo inteligente. Em vez de simplesmente injetar requisições aleatórias na parede e torcer para algo quebrar, ele aplica engenharia reversa tática:

1.  **Reconhecimento Profundo (Deep Recon):** Mapeamento agressivo de portas, descobrimento de IPs ocultos e mineração de arquivos JavaScript minificados atrás de tokens perdidos e APIs esquecidas.
2.  **Strict Validation Engine:** Motores de inteligência purificam o "Lixo HTTP", ignorando páginas de "Not Found" mentirosas (Soft 404s) e garantindo que cada vulnerabilidade relatada no seu terminal de comando seja 100% testada e provada real. Nenhum falso positivo para lotar seu relatório.
3.  **Fuzzing Mutacional Dinâmico:** Se um firewall de mercado tenta bloquear nossos testes SQLi ou XSS, o sistema recodifica e muta (Hexadecimal, Null Bytes, Double-URL Encoding) a malícia em *tempo real* para penetrar as defesas perfeitamente invisível.

---

## 🚀 Arsenal de Funcionalidades V21.0

A versão `v21.0` eleva os testes de intrusão a um nível empresarial com as seguintes ferramentas exclusivas de *Bypass* e Ataque:

*   ⚔️ **Análise Bit-a-Bit Extrema:** Nosso motor assíncrono hiper-rápido (`qasync`) desmembra o código fonte do site alvo *linha por linha*. Nenhuma tag HTML obscura, variável secreta escondida ou anomalia de Header HTTP escapa da análise tática.
*   🛡️ **Smart Proxy Manager & IP Rotation:** Sucesso em varreduras exige invisibilidade. Este módulo pega listas brutas de SOCKS4/5 públicos, inspeciona o ping de cada um, exclui conexões mortas (dead-proxies) e rotaciona o seu IP de ataque a cada 5 requisições. O *Rate-Limiting* e as proibições por Firewall quebram diante dessa barragem descentralizada.
*   🧱 **Advanced WAF Evasion (Payload Obfuscation):** Mutações matemáticas instantâneas. O PentestGPT codifica automaticamente seus injetores SQL e XSS usando escapes Unicode complexos e injeção de "Bytes Nulos" (`%00`). Ele flana pelas regras restritas de WAFs famosos da Cloudflare e AWS como se fosse tráfego seguro de um cliente comum.
*   🔓 **Smart Error Bypass (401/403/500):** Bloqueado na porta de um painel de Administrador? O sistema entra no "Modo Bruto". Ao ver um código `403 Forbidden`, o scanner manipula automaticamente regras HTTP (trocando verbos de `POST` para `GET`), e injeta sujeira e truques de *Path Normalization* (ex: tentar `target.com/%2e/admin/`) para coagir o servidor confuso a te devolver os dados confidenciais contornando seus próprios filtros de acesso.
*   ⚡ **HTTP Request Smuggling (CL.TE / TE.CL):** A joia da coroa para atacar arquiteturas cloud modernas. Dispara pacotes de rede estruturalmente imperfeitos, misturando tamanhos falsos e duplicados nos headers `Content-Length` e `Transfer-Encoding` para envenenar os balanceadores de carga front-end (Load Balancers) e acessar impunemente o backend sensível abrigado na Intranet da empresa alvo.
*   🎭 **Context-Aware Payload Encoding:** Todo e qualquer teste nocivo executado, seja uma CVE da base NVD ou um injetor SQL genérico, é dinamicamente "trilhado" (URL Encodado, Base64 Duplo, Charcode) para garantir que as strings quebradas atinjam e fujam ilesas da raspagem do servidor antes de serem explodidas.
*   🧠 **Inteligência Artificial Nativa (AI Bridge):** Um conselheiro hacker vivo dentro do seu terminal. Conectado perfeitamente via protocolo da Groq API, a aba "Script Lab" analisa o código de tráfego de saída do site e as proteções em ação, e dita on-the-fly vetores cirúrgicos novos e moldados sob medida para o ambiente específico operando com o motor Llama3 massivo.
*   🌐 **Apex Google Dork Engine:** Varredura autônoma e massiva no Google utilizando instâncias de navegadores furtivos (Playwright Headless). O motor aplica físicas realistas de movimento de mouse (Curvas de Bézier) e falsificação criptográfica de impressão digital (WebGL/Canvas) saltando o temido filtro "Unusual Traffic".
*   🧩 **Deep CAPTCHA IFrame Piercing & Audio Solver:** Resolução automatizada de reCAPTCHA V2/V3 embebidos (IFrame cross-origin). Quando o Google ataca com desafios de áudio estritos, o Nexus intercepta assincronamente o stream `.mp3`, envia para a Inteligência Neural do **Groq Whisper-Large-v3** do próprio usuário e digita a transcrição exata, derrubando o CAPTCHA de modo autônomo sem intermediários pagos.

---

## ⚙️ Instalação Passo a Passo Assistida (Windows)

O **PentestGPT** é denso tecnologicamente, mas sua adoção é intencionalmente fluida (*Plug-and-Play*). Disponibilizamos um ambiente de inicialização em Batch que dispensa conhecimento profundo em configuração de máquinas virtuais de hackers.

### O Método Automático

1. **Puxe o Arsenal para a sua Base:** Faça Download deste ZIP, ou use a engenharia `Git`:
   ```cmd
   git clone https://github.com/moisesvvanti-dev/nexus-scanner.git
   cd nexus-scanner
   ```
2. **Requisito Vital Universal (Python):** Baixe e instale localmente o **[Python 3.10 ou superior](https://www.python.org/downloads/)**. 
   > 🔴 ***AVISO IMPRESCINDÍVEL:*** *Durante a instalação do executável nativo oficial do Python, VOCÊ DEVE MARCAR a checkmark quadrada "Add Python.exe to PATH" localizada ao rodapé do instalador antes de prosseguir. Se esquecer isso, nenhuma mágica preta em Command Lines funcionará e seu Windows não entenderá a base da ferramenta.*
3. **Automação Batch de Implantação:** Dentro da raiz do repositório clonado localmente, aplique um duplo clique rápido sobre o arquivo construtor: **`install.bat`**.
4. Ele fará todo o peso massivo do ecossistema silenciosamente: 
   * Checará se o pip existe e forçará as atualizações globais em background.
   * Compilará módulos e pacotes pesados como os navegadores Playwright Fantasmas (Headless), ferramentas matemáticas e bibliotecas de rotulação e DNS pura.
5. Ao enxergar os dizeres verdes brilhantes `"Installation Completed Successfully!"`, feche a janela cmd finalizada. Seu equipamento tático está acoplado maravilhosamente bem.

> *(Para peritos Old-School em infraestrutura C.L.I, basta iniciar o clássico: `pip install -r requirements.txt`)*

---

## 💻 Interface Gráfica (Operação)

Diferente do mar cinzento cru e desmotivante dos terminais e scanners de mercado C.L.I legados, o Nexus Ultima conta com sua plataforma completa ancorada visualmente no **PySide6** renderizando folhas QSS Cyberpunk-Native. Seu painel se parece com o controle da missão de uma Red Team imersiva.

Para soltar a Interface Visual Principal do PentestGPT, puxe do terminal a seguinte instrução vital sobre a respectiva raiz da pasta:

```cmd
python main.py
```

### Protocolo Tático na UI:
O modus-operandi é instintivo e flui pelas regras de testes corporativos reais.
1. **Ponto Cego & Definição Algorítimica:** Mire a barra sangrenta da `Target URL` para o seu inimigo contratado (Ex: `https://painel-falho.com`).
2. **Calibração das Ogivas de Bypass (Ferramentas Laterais):**
   * Preencha as Checkmarks do **Deep Scan** se quiser acoplar os bots caçadores javascript nas camadas cegas do DOM (Document Object Model).
   * Assinale livremente todas as malhas avançadas do menu **BYPASS TOOLS** (IP Rotation Inteligente, Fuzzing Dom-Polling assíncrono, Smart Error Bypass para perfurar Códigos 403 e Obfuscador Avançado WAF).
3. **AI Ignition:** Enfie a sua Chave de Combate do Groq no card designado do laboratório AI caso você precise desvendar anomalias obscuras que só o LLM possa codificar durante e em meio aos testes complexos rotacionais.
4. **Fogo Livre:** Esmague o botão `[START RECON]` centralizado enquanto os LEDs indicativos varrem milhares de linhas log por segundo mapeando desastres. Extração purinha sendo cuspida no banco de texto da tela principal da sua suíte corporativa.

---

## ⚠️ AVISO LEGAL CRÍTICO & RESPONSABILIDADES PÚBLICAS ⚠️

**LEIA ATENTAMENTE ESTE AVISO ANTES DE INICIALIZAR E RODAR A EXECUÇÃO ABSOLUTA DO ARQUIVO MAIN.PY.** Ignorá-lo o exporá incontestavelmente a litígios corporativos milionários e prisão federal irredutível garantida pela lei.

1. **Propósito Exclusivo Documentado:** Este software monumental puramente metodológico (Nome-Código: "PentestGPT") é lançado e codificado **EXCLUSIVAMENTE** visando finalidades vitais para Pesquisas Acadêmicas formadoras, treinamento e conscientização computacional de laboratório fechado (*Capture The Flag* / CTFs), ou através de Suítes de Auditoria formalmente contratadas para Operações Cibernéticas Defensivas/Ofensivas Profissionais legalizadas (*Red Team* Governamental / Testes *Bug Bounty* em escopos limitados).
2. **Uso Ilegal Inadmissível ("Crime Cibernético"):** Apontar os módulos de ataque da ferramenta, emular tentativas furtivas, burlar infraestrutura perimetral em nuvem alheia, envenenar roteadores através de HTTP Request Smuggling silencioso ou furar firewalls via payloads obfuscatórios contra **QUALQUER DOMÍNIO, IP E PLATAFORMA QUE NÃO LHE PERTENÇA, OU PARA A QUAL VOCÊ NÃO EXIBA FORMAL, CONTRATUAL ESCRITA E INEQUÍVOCA PERMISSÃO DA ORGANIZAÇÃO ALVO, É ABSOLUTAMENTE ILEGAL**. Acarreta-se neste aspecto, nas infrações diretas contra o código penal Internacional de cada fronteira (Como a rígida a CFAA - Computer Fraud and Abuse Act Americana, LGPD/GDPR - Privacidade das Instâncias da União Europeia - bem como o Artigo da Invasão de Dispositivos Computacionais Brasileiros).
3. **Absolvição Perene e Vitalícia Clandestina de Culpabilidade:** O Código Criador Mestre Primário e Engenheiro Geral por de trás desta infraestrutura (`[moises vianna vanti]`), comungado integralmente também com **TODO** o compilado de eventuais coders e contribuidores terceiros atrelados ao repositório Open-Source **NÃO ASSUMEM E RENUNCIAM ABSOLUTAMENTE E PUBLICAMENTE A QUALQUER GRAU INDIVIDUAL DE RESPONSABILIDADE CÍVEL OU FINANCEIRA**, direta ou indireta, que possa derivar do porte impensado de seu código por agentes externos.
4. **Ônus Unitário Intransferível do Operador / Prejuízos de Destruição (Bugs Loss):** Conceder Denial of Service acidental contra sistemas de rede de UTI (Causas Morte Práticas), explodir o painel da AWS destruindo tabelas essenciais SQL do Banco de Dados via Fuzzing Passivo Brutal acoplado, bem como todo processo bilionário compensatório advindo dessas causas tristes, **CORRERÃO SOB O ÔNUS FINANCEIRO COMPLETO, EXCLUSIVO, VITAL E INTEIRO DO USUÁRIO FINAL** ("Aquele que opera, clica e engendra atalhos de fogo" no momento local do Start Point cibernético) sob esta flag tática da referida suíte de caça e *hacking*.

O domínio de ferramentas altamente predatórias na esfera global da tecnologia é uma armadura letal que exige controle imperativo ético em favor da moral e dos bons comportamentos.

**Jamais crie vítimas tecnológicas indefesas em sua trajetória.**
*Aja como uma espada de luz. Haja Protegidamente, eticamente. Peça sempre permissão explícita à rede em que voa.* 🛡️

---

<div align="center">
  <p>Escrito e lapidado a pulso no silêncio dos repositórios noturnos através das mãos por <b>[moises vianna vanti]</b>, sob toda as Leis e Éticas vigentes Modernas.</p>
</div>
