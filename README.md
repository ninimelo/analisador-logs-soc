# 🛡️ Analisador de Logs Web com Detecção em Tempo Real (Simulador de SIEM / SOC)

Este projeto consiste em um script de automação em Python desenvolvido para simular o trabalho prático de uma equipe de **Defesa (Blue Team / Centro de Operações de Segurança - SOC)**. Ele atua como um motor de correlação de eventos básico, analisando logs de servidores web para identificar, isolar e reportar atividades maliciosas em tempo real com uma interface visual animada via terminal.

## 🚀 Funcionalidades Técnicas

O script realiza o parsing (análise estruturada) de strings de log no formato padrão de mercado (utilizado por servidores como Apache e Nginx) através de **Expressões Regulares (Regex)**. Ele aplica heurísticas de segurança e regras de limite (thresholds) para detectar dois vetores de ataque comuns:

1. **Tentativas de Força Bruta (Brute Force):** Identifica e agrupa endereços IP que geraram múltiplas autenticações falhas consecutivas (Código de Status HTTP `401 Unauthorized`). O script dispara um alerta crítico caso o IP atinja 3 ou mais erros.
2. **Varredura Ativa de Diretórios (Web Directory Scanning):** Detecta bots automatizados tentando mapear arquivos sensíveis e painéis administrativos que não existem no servidor (Código de Status HTTP `404 Not Found` em caminhos contendo palavras-chave como `.env`, `admin`, `config`). O script dispara um alerta médio caso o IP tente acessar 2 ou mais caminhos protegidos.

## 🎥 Diferencial Visual (Simulação SOC)

O script utiliza a biblioteca `time` para desacelerar propositalmente o processamento computacional em milissegundos. Isso cria um efeito visual de **varredura em tempo real** diretamente no terminal, permitindo que o usuário assista ao robô investigando linha por linha, ativando sinalizadores temporários e consolidando os alertas ao final do processo.

## 🛠️ Tecnologias e Conceitos Utilizados

* **Python 3.x:** Linguagem base para desenvolvimento da lógica de automação.
* **Biblioteca `re` (Regex):** Manipulação de Expressões Regulares complexas para extração precisa de strings (IP, URL e Status Code).
* **Biblioteca `collections` (`Counter`):** Otimização de contagem estática e agrupamento de dados repetidos em memória.
* **Manipulação de Arquivos (I/O):** Escrita automatizada de relatórios externos estruturados utilizando codificação UTF-8.

## 📂 Estrutura do Repositório

* `analisador_soc.py`: Código-fonte principal do script automatizado (totalmente documentado linha por linha).
* `README.md`: Documentação técnica do projeto (este arquivo).

## 📋 Como Executar o Laboratório Localmente

1. Certifique-se de ter o **Python 3** instalado em sua máquina.
2. Baixe o arquivo `analisador_soc.py` para o seu computador.
3. Abra o terminal ou prompt de comando na pasta onde salvou o arquivo e execute:
   ```bash
   python analisador_soc.py
   ```
4. Assista à inspeção das linhas no terminal e, ao final, abra o arquivo `relatorio_seguranca.txt` que terá sido gerado automaticamente na mesma pasta.

## 📊 Exemplo de Saída do Relatório Gerado (`relatorio_seguranca.txt`)

```text
==================================================
S.O.C. - RELATÓRIO DE INTRUSÃO AUTOMATIZADO
Gerado em: 15/10/2026 11:45:00
==================================================

🚨 ALERTAS DE SEGURANÇA DETECTADOS:

[ALERTA CRÍTICO] Ataque de Força Bruta! IP: 203.0.113.5 estourou o limite com 3 erros seguidos.
[ALERTA MÉDIO] Varredura de Vulnerabilidades! IP: 198.51.100.12 buscou 3 diretórios protegidos.
```

## 🧠 Cenário de Aplicação Real e Mitigação
Em uma infraestrutura de segurança corporativa real, este script operaria integrado a ferramentas de contenção. O gatilho de um evento classificado como `[ALERTA CRÍTICO]` dispararia um webhook ou uma chamada de API para firewalls ativos (como **iptables**, **UFW** ou **Cloudflare API**), realizando o banimento automatizado (Null Route) do IP atacante na borda da rede e bloqueando o fluxo de ataque de forma proativa.
