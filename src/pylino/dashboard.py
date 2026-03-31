import re
from collections import Counter
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.align import Align
from rich.console import Group
import datetime

def process_dashboard(results_list, enrich_ip_func):
    """Gera tabelas visuais e estatísticas baseadas na lista de logs coletados."""
    total_errors = sum(1 for e in results_list if e['level'] in ['ERROR', 'CRITICAL'])
    
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    time_h_pattern = r'\b([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\b'
    
    ips = []
    errors_list = []
    hours_list = []
    
    for r in results_list:
        content = r['content']
        ips.extend(re.findall(ip_pattern, content))
        time_match = re.search(time_h_pattern, content)
        if time_match:
            hours_list.append(time_match.group(1) + "h")
            
        if r['level'] in ['ERROR', 'CRITICAL']:
            clean_msg = content[:60] + "..." if len(content) > 60 else content
            errors_list.append(clean_msg)
            
    # Únicos e Contadores
    unique_ips = list(set(ips))
    top_errors = Counter(errors_list).most_common(5)
    hourly_distribution = Counter(hours_list).most_common()
    hourly_distribution.sort() # Ordenar por hora crescente
    
    # 1. Estatísticas
    stats_table = Table(title="[bold cyan]Estatísticas Gerais[/bold cyan]", show_header=False, box=None)
    stats_table.add_column("Métrica", style="cyan", justify="right")
    stats_table.add_column("Valor", style="magenta", justify="left")
    
    stats_table.add_row("Total de Erros Encontrados:", str(total_errors))
    stats_table.add_row("Endereços IP Únicos:", str(len(unique_ips)))
    
    # 2. Top 5 Erros
    top_table = Table(title="[bold red]Top 5 Erros Críticos/Frequentes[/bold red]")
    top_table.add_column("Descrição", style="red")
    top_table.add_column("Ocorrências", justify="right", style="bold yellow")
    
    for err, count in top_errors:
        top_table.add_row(err, str(count))
        
    # 3. Gráfico de Barras ASCII
    chart_table = Table(title="[bold green]Volume de Logs por Hora[/bold green]", box=None, show_header=False)
    chart_table.add_column("Hora", style="cyan")
    chart_table.add_column("Histograma", style="green")
    chart_table.add_column("Qtd", justify="right")
    
    max_count = max([c for _, c in hourly_distribution] + [1]) # Evitar div 0
    # Tamanho maximo da barra
    max_bar_len = 30
    
    for hour, count in hourly_distribution:
        bar_len = int((count / max_count) * max_bar_len)
        bar = "█" * bar_len
        chart_table.add_row(f"{hour}", bar, str(count))
        
    if not hourly_distribution:
        chart_table.add_row("N/A", "Nenhuma timestamp hh:mm:ss encontrada", "0")
        
    # 4. Inteligência em IPs (OSINT)
    osint_table = Table(title="[bold purple]Varredura de Reputação (OSINT)[/bold purple]")
    osint_table.add_column("IP Detectado", style="white")
    osint_table.add_column("País GeoIP", justify="center")
    osint_table.add_column("Status Threat Intel", justify="center")
    
    c_ips = Counter(ips).most_common(5)
    for ip, _ in c_ips:
        if enrich_ip_func:
            import pylino.osint as osint
            country = osint.get_geoip_info(ip)
            rep = osint.get_ip_reputation(ip)
            osint_table.add_row(ip, country, rep)
            
    # Junta as tabelas em um painel
    return Panel(
        Group(
            Align.center(stats_table),
            Align.center(top_table),
            Align.center(chart_table),
            Align.center(osint_table) if enrich_ip_func and c_ips else ""
        ),
        title="[bold white]Dashboard Pylino Cybersecurity[/bold white]",
        expand=False,
        border_style="cyan"
    )
