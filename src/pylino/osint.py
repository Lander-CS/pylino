import requests
import geoip2.database
from typing import Dict, Tuple
import os

# Setup mock ou fallback
VT_API_KEY = os.getenv("VT_API_KEY", "")

def get_geoip_info(ip: str) -> str:
    """Retorna o país do IP. Tenta DB local, senão usa API púbica gratuita."""
    # Tentativa com geoip2 local (requer GeoLite2-Country.mmdb)
    db_path = "GeoLite2-Country.mmdb"
    if os.path.exists(db_path):
        try:
            with geoip2.database.Reader(db_path) as reader:
                response = reader.country(ip)
                return response.country.iso_code or "Unknown"
        except Exception:
            pass
            
    # Fallback silencioso pra API open-source
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if r.status_code == 200:
            data = r.json()
            return data.get("countryCode", "UNK")
    except Exception:
        pass
    return "UNK"

def get_ip_reputation(ip: str) -> str:
    """Verifica IP no VirusTotal. Retorna [SAFE] ou [MALICIOUS]. Se não houver KEY, faz mock."""
    if not VT_API_KEY:
        # Mock de demonstração focado em Pentest (Bypass / Fuzzing / SQLi)
        if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("127."):
            return "[green]SAFE (Internal)[/green]"
        elif ip == "45.33.12.1" or ip == "185.22.14.8":
            return "[bold red]MALICIOUS[/bold red]"
        return "[cyan]NEUTRAL[/cyan]"
        
    try:
        headers = {"x-apikey": VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        req = requests.get(url, headers=headers, timeout=3)
        if req.status_code == 200:
            stats = req.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                return f"[bold red]MALICIOUS ({malicious} engines)[/bold red]"
            return "[green]CLEAN[/green]"
    except Exception:
        pass
    return "[yellow]UNKNOWN[/yellow]"

def enrich_ip(ip: str) -> str:
    """Enriquece a visualização agregando GeoIP e Métrica de Reputação."""
    country = get_geoip_info(ip)
    rep = get_ip_reputation(ip)
    return f"{ip} ({country}) {rep}"
