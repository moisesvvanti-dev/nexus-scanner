import json
import requests
import time

OUTPUT_FILE = r"c:\Users\bionicdragon\Desktop\gta code\PentestGPT\data\cve1.json"

def fetch_cves():
    print("Iniciando o download massivo de CVEs do NVD...")
    print("-------------------------------------------------------------------------")
    print("Aviso Crítico: O banco de dados MUNDIAL fornece apenas a teoria.")
    print("O script criará o formato base do PentestGPT através das 6.000 mais")
    print("recentes vulnerabilidades publicadas no globo. (Cerca de 1.5 horas para concluir se fose tudo)")
    print("-------------------------------------------------------------------------\n")
    
    try:
        print("Iniciando o Loop de Extração Global da API (Buscando 6.000 records)...\n")
        
        pentestgpt_cves = []
        total_a_buscar = 6000
        resultados_por_pagina = 2000 # O limite máximo do NVD é 2000 por página
        
        for start_index in range(0, total_a_buscar, resultados_por_pagina):
            print(f"-> Varrendo blocos do índice {start_index} a {start_index + resultados_por_pagina}...")
            
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={resultados_por_pagina}&startIndex={start_index}"
            
            try:
                response = requests.get(url, timeout=45)
            except Exception as req_ex:
                print(f"Erro de Conexão na API no índice {start_index}: {req_ex}")
                break
                
            if response.status_code == 403:
                print("⚠️ O NVD bloqueou a IP temporariamente (Rate Limit Defense Excedido).")
                print("Finalizando o dump antes do limite para salvar o progresso atual...")
                break
                
            if response.status_code != 200:
                print(f"A API retornou código de erro {response.status_code}.")
                continue
                
            data = response.json()
            cve_items = data.get("vulnerabilities", [])
            
            if not cve_items:
                print("Fim dos registros globais alcançado antecipadamente.")
                break 
                
            for item in cve_items:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "Unknown CVE")
                
                descriptions = cve_data.get("descriptions", [])
                desc_value = "Descrição não disponível"
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        desc_value = desc.get("value")
                        break
                
                name_str = f"[{cve_id}] {desc_value}"
                if len(name_str) > 80:
                    name_str = name_str[:77] + "..."
                
                severity = "Unknown"
                metrics = cve_data.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    severity_data = metrics.get("cvssMetricV31", [])[0].get("cvssData", {})
                    severity = severity_data.get("baseSeverity", "Unknown")
                
                pentestgpt_cves.append({
                    "name": name_str,
                    "category": severity,
                    "type": "Auto-Generated",
                    "check_type": "path",
                    "path": "/INCLUA_O_CAMINHO_VULNERAVEL_AQUI",
                    "indicator": "O QUE ESPERAR DA RESPOSTA",
                    "status": [200, 500]
                })
            
            print(f"    + {len(cve_items)} records extraídos.")
            
            if start_index + resultados_por_pagina < total_a_buscar:
                print("    > Dormindo 6.5s para não ativar os filtros Anti-DDoS do Governo Americano...")
                time.sleep(6.5)
                
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(pentestgpt_cves, f, indent=4)
            
        print(f"\n✅ DUMP ENCERRADO COM SUCESSO! {len(pentestgpt_cves)} CVEs despejadas no arquivo {OUTPUT_FILE}")
        
    except Exception as e:
        print(f"Erro fatal não tratado no Crawler global: {e}")

if __name__ == "__main__":
    fetch_cves()
