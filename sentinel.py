#!/usr/bin/env python3
"""
SentinelTriage - CLI tool for static file analysis and IOC extraction.
Designed for InfoSec, SOC, and DFIR teams.
"""

import argparse
import sys
import os
import secrets
from core.analyzer import calculate_hashes, analyze_file_entropy, get_file_size
from core.extractors import IOCExtractor
from core.reporter import Reporter


def generate_test_file(output_path: str = "test_malware.bin"):
    """Generate a test file with fake IOCs and encrypted section."""
    # Create content with fake IOCs
    content = b"""
    Fake Malware Sample v1.0
    C2 Server: http://evil-c2-server.com/command
    Backup C2: http://192.168.1.100/panel
    Contact: attacker@evil-domain.com
    Admin: admin@malicious.net
    
    Configuration data:
    SGVsbG8gV29ybGQ=  # Base64: "Hello World"
    Q29uZmlndXJhdGlvbiBkYXRh  # Base64: "Configuration data"
    """
    
    # Add high-entropy encrypted section (random bytes)
    encrypted_section = secrets.token_bytes(1024)  # 1KB of random data
    
    # Combine content
    full_content = content + b"\n" + b"=" * 50 + b"\n" + encrypted_section
    
    # Write to file
    with open(output_path, 'wb') as f:
        f.write(full_content)
    
    print(f"Test file generated: {output_path}")
    print(f"File size: {len(full_content)} bytes")
    print("Includes fake URLs, IPs, emails, base64 strings, and high-entropy section")


def analyze_file(file_path: str, json_output: str = None):
    """Analyze a file and generate report."""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    
    # Get file size
    file_size = get_file_size(file_path)
    
    # Calculate hashes
    hashes = calculate_hashes(file_path)
    
    # Analyze entropy
    entropy_value, is_suspicious = analyze_file_entropy(file_path)
    entropy_data = {
        'value': entropy_value,
        'is_suspicious': is_suspicious
    }
    
    # Extract IOCs
    extractor = IOCExtractor(file_path)
    iocs = extractor.extract_all_iocs()
    
    # Compile analysis result
    analysis_result = {
        'file_path': file_path,
        'file_size': file_size,
        'hashes': hashes,
        'entropy': entropy_data,
        'iocs': iocs
    }
    
    # Generate report
    reporter = Reporter()
    reporter.print_report(analysis_result, file_path)
    
    # Export to JSON if requested
    if json_output:
        reporter.export_json(analysis_result, file_path, json_output)


def main():
    parser = argparse.ArgumentParser(
        description='SentinelTriage - Static file analysis and IOC extraction tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze suspicious.exe
  %(prog)s analyze suspicious.exe --json report.json
  %(prog)s --generate-test
  %(prog)s --generate-test --output test_sample.bin
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a file')
    analyze_parser.add_argument('file', help='Path to the file to analyze')
    analyze_parser.add_argument('--json', metavar='PATH', help='Export results to JSON file')
    
    # Generate test file command
    generate_parser = subparsers.add_parser('generate-test', help='Generate a test file with fake IOCs')
    generate_parser.add_argument('--output', '-o', default='test_malware.bin', 
                                  help='Output path for test file (default: test_malware.bin)')
    
    # Legacy flag support
    parser.add_argument('--generate-test', action='store_true', help='Generate a test file (legacy)')
    parser.add_argument('--output', '-o', help='Output path for generated test file')
    
    args = parser.parse_args()
    
    # Handle legacy --generate-test flag
    if args.generate_test:
        output_path = args.output if args.output else 'test_malware.bin'
        generate_test_file(output_path)
        return
    
    # Handle subcommands
    if args.command == 'analyze':
        analyze_file(args.file, args.json)
    elif args.command == 'generate-test':
        generate_test_file(args.output)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
