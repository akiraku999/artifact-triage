import json
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box


class Reporter:
    """Generate and display analysis reports using rich library."""
    
    def __init__(self):
        self.console = Console()
    
    def print_report(self, analysis_result: Dict[str, Any], file_path: str):
        """Print formatted analysis report to console."""
        self.console.print()
        
        # Header
        header = Text.assemble(
            ("🔍 ", "bold white"),
            ("SentinelTriage", "bold cyan"),
            (" - Static File Analysis", "bold white")
        )
        self.console.print(Panel(header, box.ROUNDED))
        self.console.print()
        
        # File Information
        self._print_file_info(analysis_result, file_path)
        
        # Hash Information
        self._print_hashes(analysis_result['hashes'])
        
        # Entropy Analysis
        self._print_entropy(analysis_result['entropy'])
        
        # IOC Findings
        self._print_iocs(analysis_result['iocs'])
        
        # Overall Verdict
        self._print_verdict(analysis_result)
    
    def _print_file_info(self, analysis_result: Dict[str, Any], file_path: str):
        """Print basic file information."""
        table = Table(title="File Information", box=box.SIMPLE)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Path", file_path)
        table.add_row("Size", f"{analysis_result['file_size']:,} bytes")
        
        self.console.print(table)
        self.console.print()
    
    def _print_hashes(self, hashes: Dict[str, str]):
        """Print hash values."""
        table = Table(title="File Hashes", box=box.SIMPLE)
        table.add_column("Algorithm", style="cyan")
        table.add_column("Hash", style="white")
        
        for algo, hash_value in hashes.items():
            table.add_row(algo.upper(), hash_value)
        
        self.console.print(table)
        self.console.print()
    
    def _print_entropy(self, entropy_data: Dict[str, Any]):
        """Print entropy analysis."""
        entropy = entropy_data['value']
        is_suspicious = entropy_data['is_suspicious']
        
        if is_suspicious:
            status = "[SUSPICIOUS]"
            status_style = "bold red"
        else:
            status = "[SAFE]"
            status_style = "bold green"
        
        table = Table(title="Entropy Analysis", box=box.SIMPLE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Shannon Entropy", f"{entropy:.4f}")
        table.add_row("Status", Text(status, style=status_style))
        
        self.console.print(table)
        self.console.print()
    
    def _print_iocs(self, iocs: Dict[str, Any]):
        """Print extracted IOCs."""
        table = Table(title="Extracted IOCs", box=box.SIMPLE)
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="white")
        table.add_column("Findings", style="yellow")
        
        # IPv4
        ipv4_count = len(iocs['ipv4'])
        ipv4_str = ", ".join(iocs['ipv4'][:3])
        if ipv4_count > 3:
            ipv4_str += f" ... ({ipv4_count - 3} more)"
        table.add_row("IPv4", str(ipv4_count), ipv4_str if ipv4_count else "None")
        
        # URLs
        url_count = len(iocs['urls'])
        url_str = ", ".join(iocs['urls'][:2])
        if url_count > 2:
            url_str += f" ... ({url_count - 2} more)"
        table.add_row("URLs", str(url_count), url_str if url_count else "None")
        
        # Emails
        email_count = len(iocs['emails'])
        email_str = ", ".join(iocs['emails'][:2])
        if email_count > 2:
            email_str += f" ... ({email_count - 2} more)"
        table.add_row("Emails", str(email_count), email_str if email_count else "None")
        
        # Base64
        b64_count = len(iocs['base64_strings'])
        table.add_row("Base64 Strings", str(b64_count), f"{b64_count} found" if b64_count else "None")
        
        self.console.print(table)
        self.console.print()
        
        # Print detailed base64 findings if any
        if iocs['base64_strings']:
            self._print_base64_details(iocs['base64_strings'])
    
    def _print_base64_details(self, base64_strings: list):
        """Print detailed base64 string analysis."""
        table = Table(title="Base64 String Analysis", box=box.SIMPLE)
        table.add_column("Encoded", style="cyan")
        table.add_column("Decoded", style="white")
        table.add_column("Printable", style="yellow")
        
        for b64 in base64_strings[:5]:  # Show first 5
            decoded = b64['decoded'] if b64['decoded'] else "[Failed to decode]"
            printable = "Yes" if b64['is_printable'] else "No"
            table.add_row(b64['encoded'][:50] + "...", decoded[:50] + "...", printable)
        
        if len(base64_strings) > 5:
            table.add_row("...", f"... ({len(base64_strings) - 5} more)", "...")
        
        self.console.print(table)
        self.console.print()
    
    def _print_verdict(self, analysis_result: Dict[str, Any]):
        """Print overall verdict."""
        ioc_count = (
            len(analysis_result['iocs']['ipv4']) +
            len(analysis_result['iocs']['urls']) +
            len(analysis_result['iocs']['emails']) +
            len(analysis_result['iocs']['base64_strings'])
        )
        
        entropy_suspicious = analysis_result['entropy']['is_suspicious']
        
        if entropy_suspicious or ioc_count > 0:
            verdict = "[SUSPICIOUS]"
            verdict_style = "bold red"
            reason = []
            if entropy_suspicious:
                reason.append("High entropy (>7.0)")
            if ioc_count > 0:
                reason.append(f"IOCs detected ({ioc_count})")
            reason_text = ", ".join(reason)
        else:
            verdict = "[SAFE]"
            verdict_style = "bold green"
            reason_text = "No suspicious indicators found"
        
        verdict_panel = Panel(
            Text.assemble(
                ("Overall Verdict: ", "white"),
                (verdict, verdict_style),
                (f"\n\nReason: {reason_text}", "white")
            ),
            title="FINAL ASSESSMENT",
            box=box.ROUNDED
        )
        self.console.print(verdict_panel)
        self.console.print()
    
    def export_json(self, analysis_result: Dict[str, Any], file_path: str, output_path: str):
        """Export analysis result to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(analysis_result, f, indent=2)
        self.console.print(f"[green]JSON report saved to: {output_path}[/green]")
