import asyncio
import aiohttp
import time
import json
from enum import Enum

class AuthTester:
    """
    Ferramenta de Segurança Ofensiva para testar vulnerabilidades em APIs de Autenticação do Supabase.
    Testa Enumeration de Usuários, Rate Limiting e Brute Force.
    """
    def __init__(self, target_url, api_key):
        # Assegura que a URL não termina com /
        self.target_url = target_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'apikey': self.api_key,
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'X-Client-Info': 'pentestgpt-auth-scanner/1.0'
        }

    async def run_all_tests(self):
        print(f"[*] Iniciando auditoria de Autenticação Supabase em: {self.target_url}")
        
        # Teste 1: Enumeration via Signup
        await self.test_user_enumeration("admin@example.com")
        
        # Teste 2: Brute Force & Rate Limit
        await self.test_brute_force_and_rate_limit("target@example.com", 15)

    async def test_user_enumeration(self, target_email):
        """
        Tenta descobrir se um e-mail já está registrado tentando criar uma conta.
        Se retornar erro de e-mail já existente e o painel não tiver proteção contra link scraping, vaza a info.
        """
        print(f"\\n[+] Testando Enumeração de Usuários (Alvo: {target_email})...")
        endpoint = f"{self.target_url}/auth/v1/signup"
        
        payload = {
            "email": target_email,
            "password": "Password123!SecureRandom"
        }

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(headers=self.headers, connector=connector) as session:
            async with session.post(endpoint, json=payload) as response:
                status = response.status
                text = await response.text()
                
                if status == 400 and "already registered" in text.lower():
                    print(f"  [!] VULNERABILIDADE (Info Leak): O e-mail {target_email} existe no banco de dados!")
                elif status == 200:
                    print(f"  [-] Conta criada com sucesso (o e-mail não existia ou o Supabase mockou a resposta para evitar enumeração).")
                else:
                    print(f"  [-] Resposta do servidor: {status} - {text}")

    async def test_brute_force_and_rate_limit(self, target_email, attempts=10):
        """
        Dispara múltiplas tentativas de login com senha incorreta para ver se o Rate Limiter 
        (Max emails per hour) bloqueia o ataque e protege a conta.
        """
        print(f"\\n[+] Testando Proteção contra Brute Force (Alvo: {target_email} | {attempts} tentativas)...")
        endpoint = f"{self.target_url}/auth/v1/token?grant_type=password"
        
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(headers=self.headers, connector=connector) as session:
            tasks = []
            for i in range(attempts):
                payload = {
                    "email": target_email,
                    "password": f"WrongPassword{i}!"
                }
                tasks.append(session.post(endpoint, json=payload))
            
            start_time = time.time()
            responses = await asyncio.gather(*tasks)
            elapsed = time.time() - start_time
            
            rate_limit_hit = False
            for i, resp in enumerate(responses):
                text = await resp.text()
                if resp.status == 429: # Too Many Requests
                    rate_limit_hit = True
                    print(f"  [✓] RATE LIMIT ATIVADO na tentativa {i+1}! Defesa funcionou.")
                    break
                elif resp.status == 403 or resp.status == 400:
                    # Invalid login credentials
                    pass

            if not rate_limit_hit:
                print(f"  [!] VULNERABILIDADE: Nenhuma limitação de taxa (Rate Limit) detectada em {attempts} tentativas. O alvo é suscetível a Brute Force e Credential Stuffing.")
            
            print(f"  [-] {attempts} requisições completadas em {elapsed:.2f} segundos.")

if __name__ == "__main__":
    # Exemplo de uso
    url = input("Supabase Project URL (ex: https://xyz.supabase.co): ")
    key = input("Supabase ANON KEY: ")
    
    if url and key:
        tester = AuthTester(url, key)
        asyncio.run(tester.run_all_tests())
