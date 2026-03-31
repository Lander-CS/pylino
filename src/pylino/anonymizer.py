import re

# Padrões comuns de PII para mascaramento (Fake/Exemplo) - COMPLIANCE LGPD
PII_PATTERNS = {
    "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "CPF": r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b",
    "IP": r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
}

def mask_pii(text: str) -> str:
    """Aplica máscaras em PIIs encontradas no texto (LGPD compliance)."""
    masked_text = text
    for pii_type, pattern in PII_PATTERNS.items():
        masked_text = re.sub(pattern, f"[MASCARADO-{pii_type}]", masked_text)
    return masked_text
