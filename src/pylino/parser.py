import re
import os
import time
import json
import csv
from io import StringIO
from typing import Iterator, Optional, Dict
from pylino.anonymizer import mask_pii

def read_logs_lazy(filepath: str, tail: bool = False) -> Iterator[str]:
    """Lê o arquivo de log linha por linha usando gerador (Performance)."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        if tail:
            f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                if tail:
                    time.sleep(0.1)
                    continue
                else:
                    break
            yield line.strip()

def parse_and_filter(
    filepath: str, 
    level: Optional[str] = None, 
    date: Optional[str] = None, 
    pattern: Optional[str] = None,
    anonymize: bool = True,
    tail: bool = False
) -> Iterator[Dict[str, str]]:
    """Filtra as linhas baseado em critérios e retorna um dicionário com os metadados."""
    
    # Validação de Segurança contra Prompt/Regex Injection
    if pattern:
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Padrão Regex inválido: {e}")

    for line in read_logs_lazy(filepath, tail):
        # Filtros rápidos
        if level and level.upper() not in line:
            continue
            
        if date and date not in line:
            continue
            
        if pattern and not re.search(pattern, line):
            continue

        # Parsing Automático de Formatos (JSON/CSV)
        parsed_obj = None
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed_obj = json.loads(line)
                line_to_process = json.dumps(parsed_obj, ensure_ascii=False)
            except json.JSONDecodeError:
                line_to_process = line
        elif "," in line or "\t" in line:
            try:
                # Simples tratamento para CSV/TSV
                delim = '\t' if '\t' in line else ','
                f_io = StringIO(line)
                row = next(csv.reader(f_io, delimiter=delim))
                line_to_process = " | ".join(row)
            except Exception:
                line_to_process = line
        else:
            line_to_process = line

        # Processamento e Anonimização (LGPD)
        processed_line = mask_pii(line_to_process) if anonymize else line_to_process
        
        # Tenta extrair level para exibição elegante (heurística básica)
        extracted_level = "UNKNOWN"
        for l in ["INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG"]:
            if l in line:
                extracted_level = l
                break
                
        # Se for JSON, também podemos tentar encontrar o level nas chaves
        if isinstance(parsed_obj, dict):
            for k, v in parsed_obj.items():
                if isinstance(v, str) and str(v).upper() in ["INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG"]:
                    extracted_level = str(v).upper()
                    break

        yield {
            "level": extracted_level,
            "content": processed_line
        }
