import click
from rich.console import Console
from rich.table import Table
from pylino.parser import parse_and_filter

console = Console()

@click.command()
@click.argument('filepath', type=click.Path(exists=True, readable=True))
@click.option('--level', '-l', help='Filtrar por nível de severidade (INFO, WARNING, ERROR, CRITICAL)')
@click.option('--date', '-d', help='Filtrar por data específica (ex: 2023-10-25)')
@click.option('--pattern', '-p', help='Filtrar por padrão Regex')
@click.option('--tail', '-t', is_flag=True, help='Escutar o arquivo em tempo real (Tail -f)')
@click.option('--osint', is_flag=True, help='Ativar pesquisa OSINT/GeoIP (VirusTotal & Threat Intel)')
@click.option('--dashboard', is_flag=True, help='Exibir um Dashboard interativo com gráficos HTML/Terminal')
@click.option('--no-anonymize', is_flag=True, help='Desativar anonimização de dados (Risco LGPD/GDPR)')
def cli(filepath, level, date, pattern, tail, osint, dashboard, no_anonymize):
    """
    Pylino - Ferramenta CLI para Análise de Arquivos de Log.
    
    Garante alta performance utilizando geradores e Compliance
    com LGPD mascarando PIIs (emails, CPFs, IPs) por padrão.
    Suporta parsing automático de JSON e CSV.
    """
    anonymize = not no_anonymize
    
    if not anonymize:
        console.print("[bold yellow]Aviso de Segurança: Anonimização LGPD desativada pelo usuário.[/bold yellow]")

    try:
        results = parse_and_filter(filepath, level, date, pattern, anonymize, tail)
        
        if tail:
            console.print(f"[bold cyan]>>> Monitorando {filepath} em tempo real (Aperte Ctrl+C para sair)...[/bold cyan]")
            count = 0
            for entry in results:
                count += 1
                lvl = entry["level"]
                content = entry.get("content", "")
                
                if lvl in ["ERROR", "CRITICAL"]:
                    lvl_str = f"[bold red]{lvl}[/bold red]"
                elif lvl == "WARNING":
                    lvl_str = f"[bold yellow]{lvl}[/bold yellow]"
                elif lvl == "INFO":
                    lvl_str = f"[bold green]{lvl}[/bold green]"
                else:
                    lvl_str = f"[bold white]{lvl}[/bold white]"
                    
                console.print(f"{lvl_str} | {content}")
        elif dashboard:
            import pylino.dashboard as dash
            import pylino.osint as osnt
            
            # Precisamos extrair toda a lista para processamento analítico e montar as tabelas
            res_list = list(results)
            console.print("[bold cyan]⠋ Montando engine de estatísticas e painéis visuais...[/bold cyan]")
            
            painel = dash.process_dashboard(res_list, enrich_ip_func=True if osint else False)
            console.print(painel)
            
            console.print(f"\n[bold green]✓[/bold green] Fim da análise de SOC. {len(res_list)} artefatos processados.")
            
        else:
            table = Table(title=f"Análise de Logs: {filepath}", show_lines=False)
            table.add_column("Level", justify="center", style="cyan", no_wrap=True)
            table.add_column("Conteúdo", style="white")

            count = 0
            for entry in results:
                count += 1
                lvl = entry["level"]
                content = entry.get("content", "")
                
                # Formatação de cores no Rich
                if lvl == "ERROR" or lvl == "CRITICAL":
                    lvl_str = f"[bold red]{lvl}[/bold red]"
                elif lvl == "WARNING":
                    lvl_str = f"[bold yellow]{lvl}[/bold yellow]"
                elif lvl == "INFO":
                    lvl_str = f"[bold green]{lvl}[/bold green]"
                else:
                    lvl_str = lvl
                    
                table.add_row(lvl_str, str(content))
                
            console.print(table)
            console.print(f"\n[bold green]✓[/bold green] Fim da análise padrão. {count} linhas filtradas.")

    except ValueError as ve:
        console.print(f"[bold red]Erro de Validação:[/bold red] {str(ve)}")
    except KeyboardInterrupt:
        console.print(f"\n[bold green]✓[/bold green] Monitoramento encerrado pelo usuário.")
    except Exception as e:
        console.print(f"[bold red]Erro Inesperado:[/bold red] {str(e)}")

if __name__ == '__main__':
    cli()
