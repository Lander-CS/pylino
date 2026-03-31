import re
from typing import Iterator, Optional, Dict
from pylino.anonymizer import mask_pii

def read_logs_lazy(filepath: str) -> Iterator[str]:
    """Lê o arquivo de log linha por linha usando gerador (Performance)."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            yield line.strip()

def parse_and_filter(
    filepath: str, 
    level: Optional[str] = None, 
    date: Optional[str] = None, 
    pattern: Optional[str] = None,
    anonymize: bool = True
) -> Iterator[Dict[str, str]]:
    """Filtra as linhas baseado em critérios e retorna um dicionário com os metadados."""
    
    # Validação de Segurança contra Prompt/Regex Injection
    if pattern:
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Padrão Regex inválido: {e}")

    for line in read_logs_lazy(filepath):
        # Filtros rápidos
        if level and level.upper() not in line:
            continue
            
        if date and date not in line:
            continue
            
        if pattern and not re.search(pattern, line):
            continue

        # Processamento e Anonimização (LGPD)
        processed_line = mask_pii(line) if anonymize else line
        
        # Tenta extrair timestamp e level para exibição elegante (heurística básica)
        extracted_level = "UNKNOWN"
        for l in ["INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG"]:
            if l in line:
                extracted_level = l
                break
                
        yield {
            "level": extracted_level,
            "content": processed_line
        }
