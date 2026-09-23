import sys
import json
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.markup import escape
from rich import box


class Reporter:
    """Generate and display analysis reports using rich library."""
    
    def __init__(self):
        self.console = Console(safe_box=True)
    
    def _get_header_icon(self) -> str:
        """Return safe icon depending on terminal encoding support."""
        encoding = getattr(sys.stdout, 'encoding', None) or 'utf-8'
        try:
            "🔍".encode(encoding)
            return "🔍 "
        except Exception:
            return "[*] "
    
    def print_report(self, analysis_result: Dict[str, Any], file_path: str):
        """Print formatted analysis report to console."""
        self.console.print()
        
        # Header
        header = Text.assemble(
            (self._get_header_icon(), "bold white"),
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
        
        # PE Information (if PE binary)
        pe_info = analysis_result.get('pe_info', {})
        if pe_info.get('is_pe'):
            self._print_pe_sections(pe_info)
            self._print_pe_suspicious_apis(pe_info)
        
        # IOC Findings
        self._print_iocs(analysis_result['iocs'])
        
        # Overall Verdict
        self._print_verdict(analysis_result)
    
    def _print_file_info(self, analysis_result: Dict[str, Any], file_path: str):
        """Print basic file and PE information."""
        table = Table(title="File Information", box=box.SIMPLE)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Path", file_path)
        table.add_row("Size", f"{analysis_result['file_size']:,} bytes")
        
        pe_info = analysis_result.get('pe_info', {})
        if pe_info.get('is_pe'):
            table.add_row("Format", "Windows Portable Executable (PE)")
            table.add_row("Architecture", pe_info.get('architecture', 'Unknown'))
            table.add_row("Subsystem", pe_info.get('subsystem', 'Unknown'))
            
            comp_time = pe_info.get('compile_time', 'Unknown')
            if pe_info.get('is_suspicious_time'):
                comp_time += " [bold yellow](Suspicious/Anomalous)[/bold yellow]"
            table.add_row("Compile Time", comp_time)
            
            sig_text = "[bold green]Signed (Authenticode present)[/bold green]" if pe_info.get('is_signed') else "[yellow]Unsigned[/yellow]"
            table.add_row("Signature", sig_text)
            
            if pe_info.get('detected_packers'):
                table.add_row("Packer Detected", f"[bold red]{', '.join(pe_info['detected_packers'])}[/bold red]")
        
        self.console.print(table)
        self.console.print()
    
    def _print_pe_sections(self, pe_info: Dict[str, Any]):
        """Print PE sections and their entropy."""
        table = Table(title="PE Sections Analysis", box=box.SIMPLE)
        table.add_column("Name", style="cyan")
        table.add_column("Virt Size", style="white")
        table.add_column("Raw Size", style="white")
        table.add_column("Entropy", style="white")
        table.add_column("Status / Flags", style="yellow")
        
        for sec in pe_info.get('sections', []):
            name = sec['name'] or "[anonymous]"
            v_size = f"{sec['virtual_size']:,} B"
            r_size = f"{sec['raw_size']:,} B"
            entropy_str = f"{sec['entropy']:.4f}"
            
            if sec['is_suspicious']:
                status = f"[bold red][SUSPICIOUS] {sec['reasons']}[/bold red]"
            else:
                status = "[green][NORMAL][/green]"
            
            table.add_row(name, v_size, r_size, entropy_str, status)
            
        self.console.print(table)
        self.console.print()
        
    def _print_pe_suspicious_apis(self, pe_info: Dict[str, Any]):
        """Print suspicious WinAPI imports grouped by capability."""
        susp_apis = pe_info.get('suspicious_apis', {})
        if not susp_apis:
            return
            
        table = Table(title="Suspicious WinAPI Imports", box=box.SIMPLE)
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="white")
        table.add_column("Detected APIs", style="yellow")
        
        for category, funcs in susp_apis.items():
            func_str = ", ".join(funcs[:4])
            if len(funcs) > 4:
                func_str += f" ... ({len(funcs) - 4} more)"
            table.add_row(category, str(len(funcs)), func_str)
            
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
        
        ipv4_details = iocs.get('ipv4_details', {})
        public_ips = ipv4_details.get('public', [])
        private_ips = ipv4_details.get('private', [])
        
        # Public IPv4
        pub_count = len(public_ips)
        pub_str = ", ".join(public_ips[:3])
        if pub_count > 3:
            pub_str += f" ... ({pub_count - 3} more)"
        table.add_row("IPv4 (Public)", str(pub_count), escape(pub_str) if pub_count else "None")
        
        # Private/Local IPv4
        priv_count = len(private_ips)
        priv_str = ", ".join(private_ips[:3])
        if priv_count > 3:
            priv_str += f" ... ({priv_count - 3} more)"
        table.add_row("IPv4 (Private/Local)", str(priv_count), escape(priv_str) if priv_count else "None")
        
        # URLs
        url_count = len(iocs['urls'])
        url_str = ", ".join(iocs['urls'][:2])
        if url_count > 2:
            url_str += f" ... ({url_count - 2} more)"
        table.add_row("URLs", str(url_count), escape(url_str) if url_count else "None")
        
        # Emails
        email_count = len(iocs['emails'])
        email_str = ", ".join(iocs['emails'][:2])
        if email_count > 2:
            email_str += f" ... ({email_count - 2} more)"
        table.add_row("Emails", str(email_count), escape(email_str) if email_count else "None")
        
        # Base64
        b64_count = len(iocs['base64_strings'])
        decoded_count = sum(1 for b in iocs['base64_strings'] if b.get('is_printable'))
        b64_summary = f"{b64_count} found ({decoded_count} decoded printable)" if b64_count else "None"
        table.add_row("Base64 Strings", str(b64_count), b64_summary)
        
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
            decoded = b64['decoded'] if b64['decoded'] else "[Non-text payload]"
            printable = "Yes" if b64['is_printable'] else "No"
            table.add_row(b64['encoded'][:50] + "...", decoded[:50] + "...", printable)
        
        if len(base64_strings) > 5:
            table.add_row("...", f"... ({len(base64_strings) - 5} more)", "...")
        
        self.console.print(table)
        self.console.print()
    
    def _print_verdict(self, analysis_result: Dict[str, Any]):
        """Print overall verdict."""
        entropy_suspicious = analysis_result['entropy']['is_suspicious']
        
        iocs = analysis_result['iocs']
        ipv4_details = iocs.get('ipv4_details', {})
        public_ips = ipv4_details.get('public', [])
        private_ips = ipv4_details.get('private', [])
        urls = iocs.get('urls', [])
        emails = iocs.get('emails', [])
        base64_strings = iocs.get('base64_strings', [])
        printable_b64 = [b for b in base64_strings if b.get('is_printable')]
        
        critical_iocs = len(public_ips) + len(urls) + len(emails)
        suspicious_b64_count = len(printable_b64)
        
        reasons = []
        if entropy_suspicious:
            reasons.append("High entropy (>7.0, possible packed/encrypted)")
        if public_ips:
            reasons.append(f"Public IP(s) detected ({len(public_ips)})")
        if urls:
            reasons.append(f"External URL(s) detected ({len(urls)})")
        if emails:
            reasons.append(f"Email(s) detected ({len(emails)})")
        if suspicious_b64_count > 0:
            reasons.append(f"Decoded Base64 payload(s) found ({suspicious_b64_count})")
        
        # PE specific indicators
        pe_info = analysis_result.get('pe_info', {})
        pe_suspicious = False
        if pe_info.get('is_pe'):
            if pe_info.get('detected_packers'):
                reasons.append(f"Known packer detected ({', '.join(pe_info['detected_packers'])})")
                pe_suspicious = True
            if pe_info.get('has_suspicious_sections'):
                reasons.append("Suspicious PE section(s) with high entropy or anomalies")
                pe_suspicious = True
            if pe_info.get('total_suspicious_apis', 0) > 0:
                reasons.append(f"Suspicious WinAPI calls detected ({pe_info['total_suspicious_apis']})")
                pe_suspicious = True
            if pe_info.get('is_suspicious_time'):
                reasons.append("Anomalous compilation timestamp")
        
        if entropy_suspicious or critical_iocs > 0 or suspicious_b64_count > 0 or pe_suspicious:
            verdict = "[SUSPICIOUS]"
            verdict_style = "bold red"
            reason_text = ", ".join(reasons)
        elif private_ips or len(base64_strings) > 0:
            verdict = "[LOW RISK / INFORMATIONAL]"
            verdict_style = "bold yellow"
            reason_parts = []
            if private_ips:
                reason_parts.append(f"Internal/private IP(s) only ({len(private_ips)})")
            if base64_strings:
                reason_parts.append(f"Raw Base64 string(s) without printable payload ({len(base64_strings)})")
            reason_text = ", ".join(reason_parts)
        else:
            verdict = "[SAFE]"
            verdict_style = "bold green"
            reason_text = "No suspicious indicators or anomalous entropy found"
        
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
