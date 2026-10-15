import re  # Importa a biblioteca de Expressões Regulares para fazer a busca de padrões no texto
import time  # Importa a biblioteca de tempo para criar os intervalos de animação no terminal
from collections import Counter  # Importa o utilitário para contar e agrupar elementos repetidos
from datetime import datetime  # Importa a biblioteca de data e hora para carregar o momento do relatório

# ==============================================================================
# BASE DE DADOS EMBUTIDA (MOCK DATA)
# Simula strings reais de logs coletadas de um servidor web corporativo (Apache/Nginx)
# ==============================================================================
logs_servidor = [
    '192.168.1.50 - - [13/Oct/2026:10:01:00] "GET /index.html HTTP/1.1" 200',
    '203.0.113.5 - - [13/Oct/2026:10:02:01] "POST /login HTTP/1.1" 401',  # Erro de Senha (1)
    '203.0.113.5 - - [13/Oct/2026:10:02:02] "POST /login HTTP/1.1" 401',  # Erro de Senha (2)
    '203.0.113.5 - - [13/Oct/2026:10:02:03] "POST /login HTTP/1.1" 401',  # Erro de Senha (3) -> Estoura o limite!
    '192.168.1.55 - - [13/Oct/2026:10:03:15] "GET /images/logo.png HTTP/1.1" 200',
    '198.51.100.12 - - [13/Oct/2026:10:04:10] "GET /admin HTTP/1.1" 404',  # Pasta Sensível (1)
    '198.51.100.12 - - [13/Oct/2026:10:04:12] "GET /.env HTTP/1.1" 404',   # Arquivo Config (2) -> Estoura o limite!
    '198.51.100.12 - - [13/Oct/2026:10:04:15] "GET /wp-admin HTTP/1.1" 404',# Painel Admin (3)
    '192.168.1.50 - - [13/Oct/2026:10:05:00] "GET /dashboard.html HTTP/1.1" 200'
]

# Listas de triagem para armazenar temporariamente os IPs suspeitos encontrados
ips_forca_bruta = []
ips_varredura = []

print("=== INICIANDO VARREDURA DO S.O.C. IN REAL-TIME ===")

# ==============================================================================
# ETAPA 1: CRONOGRAMA DE INSPEÇÃO (PARSING COM ANIMAÇÃO)
# O comando 'enumerate(..., 1)' serve para contar as linhas começando do número 1
# ==============================================================================
for num, log in enumerate(logs_servidor, 1):
    # Exibe visualmente qual linha o script está inspecionando no milissegundo atual
    print(f"🔍 Investigando linha {num}...")
    time.sleep(0.4)  # Pausa o terminal por 0.4 segundos para criar o efeito visual de leitura

    # EXPRESSÃO REGULAR (REGEX): Fatiador estruturado de logs
    # (\d+\.\d+\.\d+\.\d+) -> Filtra e isola o IP do cliente
    # [A-Z]+\s(\S+)        -> Localiza o método (GET/POST) e isola o caminho da URL acessada
    # \s(\d+)              -> Filtra e isola os 3 dígitos do código de resposta HTTP
    match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?"[A-Z]+\s(\S+)\s.*?"\s(\d+)', log)
    
    if match:
        # Extrai os dados validados dos grupos da Regex para variáveis limpas
        ip, url, status = match.groups()
        
        # REGRA DE SEGURANÇA 1: Identificação de erros de credenciais (Código 401)
        if status == '401':
            print(f"   ⚠️ [Sinalizador] Falha de autenticação detectada vinda do IP {ip}")
            ips_forca_bruta.append(ip)  # Aloca o IP na lista de suspeitos de Brute Force
            
        # REGRA DE SEGURANÇA 2: Mapeamento de varredura maliciosa de diretórios (Código 404)
        # O comando 'any(...)' checa se alguma das palavras administrativas está dentro da URL tentada
        if status == '404' and any(termo in url for termo in ['admin', '.env', 'config']):
            print(f"   ⚠️ [Sinalizador] Tentativa de acesso à página restrita ({url}) pelo IP {ip}")
            ips_varredura.append(ip)  # Aloca o IP na lista de suspeitos de Web Scanning

# ==============================================================================
# ETAPA 2: CORRELAÇÃO DE EVENTOS (APLICAÇÃO DOS THRESHOLDS)
# ==============================================================================
print("\n🧮 Correlacionando eventos e aplicando regras de inteligência de segurança...")
time.sleep(1.5)  # Simula o processamento matemático do motor de correlação do SIEM

# O Counter agrupa os IPs e soma as repetições. Ex do resultado interno: {'203.0.113.5': 3}
contagem_bruta = Counter(ips_forca_bruta)
contagem_varredura = Counter(ips_varredura)

print("\n🚨 ALERTAS DE SEGURANÇA CONSOLIDADOS:")

# ==============================================================================
# ETAPA 3: GERANDO ARQUIVO DE AUDITORIA EXTERNO (.txt)
# O modo 'w' abre o arquivo escrevendo por cima, garantindo a atualização do relatório
# ==============================================================================
with open("relatorio_seguranca.txt", "w", encoding="utf-8") as arquivo:
    # Insere o cabeçalho técnico e a data/hora exata do processamento do incidente
    arquivo.write("==================================================\n")
    arquivo.write("S.O.C. - RELATÓRIO DE INTRUSÃO AUTOMATIZADO\n")
    arquivo.write(f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
    arquivo.write("==================================================\n\n")

    # GATILHO DA REGRA 1: Força bruta ativa
    # Se o mesmo IP errou logins 3 ou mais vezes (Threshold >= 3), o alarme crítico é disparado
    for ip, qtd in contagem_bruta.items():
        if qtd >= 3:
            linha = f"[ALERTA CRÍTICO] Ataque de Força Bruta! IP: {ip} estourou o limite com {qtd} erros seguidos.\n"
            print(linha.strip())  # Exibe o alerta no terminal
            arquivo.write(linha)  # Escreve o alerta dentro do arquivo de texto

    # GATILHO DA REGRA 2: Varredura de sistema ativa
    # Se o mesmo IP gerou erro 404 em 2 ou mais caminhos protegidos, o alarme médio é disparado
    for ip, qtd in contagem_varredura.items():
        if qtd >= 2:
            linha = f"[ALERTA MÉDIO] Varredura de Vulnerabilidades! IP: {ip} buscou {qtd} diretórios protegidos.\n"
            print(linha.strip())  # Exibe o alerta no terminal
            arquivo.write(linha)  # Escreve o alerta dentro do arquivo de texto

print("\n==================================================")
print("✅ PROCESSO FINALIZADO!")
print("📄 O arquivo 'relatorio_seguranca.txt' foi atualizado na pasta.")
print("==================================================")
