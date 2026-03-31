<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Security-LGPD%20Compliant-success" alt="LGPD Compliance">
  <img src="https://img.shields.io/badge/Interface-Rich%20UI-purple" alt="Rich UI">
  <img src="https://img.shields.io/badge/Memory-O(1)-orange" alt="Performance">
</p>

# Pylino CLI 🛡️

**Pylino** é uma ferramenta de linha de comando (CLI) projetada por especialistas de segurança para análise de arquivos de logs em alta performance e estrita conformidade técnica com normas de privacidade de dados (como LGPD, GDPR e HIPAA).

Seu diferencial técnico baseia-se em varreduras *Lazy Evaluation* que preservam memória RAM em máquinas de produção, combinadas com uma robusta engine de anonimização (Mascaração de PII) *built-in*, mitigando risco de vazamentos de dados sensíveis ao analisar artefatos do servidor.

---

## 🚀 Principais Funcionalidades

- **Proteção por Design (Privacy-First)**: Intercepta e mascara dados de infraestrutura ou usuários (IPs, Emails, CPFs) via Regex antes da exibição visual.
- **Eficiência Absoluta em Larga Escala**: Leia arquivos de log massivos (ex: 50GB+) sem sobrecarregar a memória do sistema utilizando blocos de *Python Generators* (Lazy Yield).
- **Interface Profissional**: Saída colorida, tabular e interpretada através de tabelas visuais usando a biblioteca `rich`.
- **Filtros Multifatoriais**: Capacidade de pesquisar linhas através de severidades, datas ou Regex personalizadas (com validação anti *Prompt Injection*).
- **Parsing Dinâmico Inteligente**: Suporte automático a múltiplos formatos, processando nativamente logs textuais, estruturas JSON (Docker, Kubernetes) ou dicionários CSV/TSV.
- **Auditoria em Tempo Real (Tail -f)**: Opcionalidade de escutar eventos em tempo real enquanto o arquivo cresce, ideal para detecções vivas ou pentest *on the fly*.

---

## 🛠️ Instalação (Modo Ferramenta)

Pylino utiliza metadados modernos padrão `pyproject.toml`. O ambiente recomendado é instalar em _Editable Mode_ (Modo de desenvolvimento) usando seu gerenciador Python preferido.

```bash
# Clone ou acesse o diretório do projeto
cd pylino

# Instale as dependências e registre o Entry Point binário globalmente
pip install -e .
```

*Nota:* Ao término, o executável `pylino` passa a integrar diretamente o `PATH` nativo do seu terminal ou ambiente virtual (venv), sem necessidade de prefixar com o binário original (ex: não é mais necessário `python main.py`).

---

## 📖 Como Usar

A CLI conta com comandos expressivos para extrair exatamente o que você precisa do seu log de forma segura. O suporte completo de `/help` está implementado.

```bash
pylino --help
```

### Casos de Uso Comuns

**1. Analisar todas as falhas e exceções críticas:**
```bash
pylino server_access.log --level ERROR
```

**2. Isolar ocorrências de um respectivo dia com output estruturado:**
```bash
pylino api_gateway.log --level WARNING --date "2023-11-20"
```

**3. Busca Complexa e Avançada (Regex Pattern):**
```bash
pylino proxy_auth.log --pattern "Timeout|Connection Reset"
```

**4. Monitoramento e Auditoria Vivaz (Tail -f em tempo real):**
```bash
# Monitora a inserção de novos erros no arquivo à medida que ocorrem
pylino production.log --tail --level ERROR
```

### Segurança Avançada: Bypass de Anonimização (Modo Auditoria)

Por padrão, regras estritas de Compliance estão **ATIVAS**. CPFs e E-mails aparecerão como `[MASCARADO-EMAIL]`. Caso seja estritamente necessário processar os dados em texto plano para forenses e você possua autorização documentada do DPO, insira a flag de bypass:

```bash
# WARNING: Ao executar isso, um Alerta de falha de segurança intencional será exibido e documentado pelo terminal.
pylino dump.log --no-anonymize
```

---

## 🔒 Arquitetura de Compliance & Revisão Humana

* **Regex Injection Defense:** Regras de input injetadas por usuários em comandos de terminal são previamente compiladas num sandbox nativo da linguagem antes de interagir via ponteiro com o arquivo no disco;
* **Extensibilidade Orientada à Segurança:** Se você atua em indústrias financeiras (PCI DSS) ou saúde (HIPAA), exija de seu time ou DPO que expanda o dicionário da estrutura nativa do arquivo nativo `anonymizer.py` com novas regras, garantindo o rastreio da cadeia customizada para a arquitetura alvo.

---
*Escrito com zelo por profissionais de Engenharia de Software focados em DevSecOps.*
