import datetime
from typing import Dict, Any, List, Optional
import pefile
from core.analyzer import calculate_entropy


# Known suspicious packer/crypter section names
KNOWN_PACKER_SECTIONS = {
    'UPX0': 'UPX',
    'UPX1': 'UPX',
    'UPX2': 'UPX',
    'ASPack': 'ASPack',
    '.aspack': 'ASPack',
    '.fsg': 'FSG',
    '.petite': 'Petite',
    '.themida': 'Themida',
    '.vmp0': 'VMProtect',
    '.vmp1': 'VMProtect',
    '.enigma': 'Enigma',
    'PEC2': 'PECompact',
    'PECompact2': 'PECompact',
}

# Categorized suspicious Windows API functions
SUSPICIOUS_API_RULES = {
    "Process Injection": [
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", 
        "CreateRemoteThread", "QueueUserAPC", "NtQueueApcThread", 
        "RtlCreateUserThread", "SetThreadContext", "ResumeThread"
    ],
    "Defense Evasion": [
        "VirtualProtect", "VirtualProtectEx", "IsDebuggerPresent", 
        "CheckRemoteDebuggerPresent", "NtSetInformationThread"
    ],
    "Dropper / Network": [
        "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
        "InternetOpen", "InternetOpenA", "InternetOpenW",
        "InternetOpenUrl", "InternetOpenUrlA", "InternetOpenUrlW",
        "HttpOpenRequest", "HttpOpenRequestA", "HttpOpenRequestW",
        "WinHttpOpen", "WSAStartup", "connect"
    ],
    "Execution / Persistence": [
        "CreateProcess", "CreateProcessA", "CreateProcessW",
        "WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
        "RegSetValueEx", "RegSetValueExA", "RegSetValueExW"
    ],
    "Spying / Keylogging": [
        "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
        "GetAsyncKeyState", "GetKeyState", "GetForegroundWindow"
    ]
}


class PEAnalyzer:
    """Analyze Portable Executable (PE) binaries for DFIR triage."""

    def __init__(self, file_path: str):
        self.file_path = file_path

    def is_pe_file(self) -> bool:
        """Quick check whether file has DOS MZ header."""
        try:
            with open(self.file_path, 'rb') as f:
                header = f.read(2)
                return header == b'MZ'
        except Exception:
            return False

    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive PE analysis."""
        if not self.is_pe_file():
            return {'is_pe': False}

        try:
            pe = pefile.PE(self.file_path, fast_load=False)
        except pefile.PEFormatError:
            return {'is_pe': False, 'error': 'Invalid PE format'}
        except Exception as e:
            return {'is_pe': False, 'error': str(e)}

        try:
            # 1. Architecture & Machine
            machine_code = pe.FILE_HEADER.Machine
            if machine_code == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                architecture = 'x64 (64-bit)'
            elif machine_code == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                architecture = 'x86 (32-bit)'
            elif machine_code == pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_ARM64', 0xAA64):
                architecture = 'ARM64'
            else:
                architecture = f'Other (0x{machine_code:04x})'

            # 2. Subsystem
            subsystem_id = getattr(pe.OPTIONAL_HEADER, 'Subsystem', None)
            subsystem_map = {
                1: 'Native / Driver',
                2: 'Windows GUI',
                3: 'Windows Console (CUI)',
                7: 'POSIX CUI',
                9: 'Windows CE GUI'
            }
            subsystem = subsystem_map.get(subsystem_id, f'Unknown ({subsystem_id})')

            # 3. Compile Time (TimeDateStamp)
            timestamp = pe.FILE_HEADER.TimeDateStamp
            try:
                compile_datetime = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
                compile_time_str = compile_datetime.strftime("%Y-%m-%d %H:%M:%S UTC")
                current_year = datetime.datetime.now(datetime.timezone.utc).year
                is_suspicious_time = compile_datetime.year < 1995 or compile_datetime.year > (current_year + 1)
            except Exception:
                compile_time_str = f"Invalid timestamp (0x{timestamp:08x})"
                is_suspicious_time = True

            # 4. Signature / Authenticode check
            is_signed = False
            try:
                sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
                if sec_dir.VirtualAddress > 0 and sec_dir.Size > 0:
                    is_signed = True
            except Exception:
                pass

            # 5. Section Analysis
            sections = []
            detected_packers = set()
            has_suspicious_sections = False

            for section in pe.sections:
                try:
                    name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                except Exception:
                    name = section.Name.decode('latin-1', errors='ignore').strip('\x00')

                section_data = section.get_data()
                sec_entropy = calculate_entropy(section_data)
                is_high_entropy = sec_entropy > 7.0
                
                # Check for known packer section names
                clean_name = name.strip()
                matched_packer = KNOWN_PACKER_SECTIONS.get(clean_name)
                if matched_packer:
                    detected_packers.add(matched_packer)

                reasons = []
                if is_high_entropy:
                    reasons.append("High entropy (>7.0)")
                if matched_packer:
                    reasons.append(f"Packer signature ({matched_packer})")
                
                # Check virtual size vs raw data size disparity
                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                    reasons.append("Uninitialized memory section (Zero raw size)")

                is_sec_suspicious = len(reasons) > 0
                if is_sec_suspicious:
                    has_suspicious_sections = True

                sections.append({
                    'name': name,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': round(sec_entropy, 4),
                    'is_suspicious': is_sec_suspicious,
                    'reasons': ", ".join(reasons) if reasons else None
                })

            # 6. Imports & Suspicious API Detection
            imported_dlls = []
            suspicious_apis: Dict[str, List[str]] = {cat: [] for cat in SUSPICIOUS_API_RULES}
            total_suspicious_count = 0

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                    except Exception:
                        dll_name = str(entry.dll)
                    imported_dlls.append(dll_name)

                    for imp in entry.imports:
                        if not imp.name:
                            continue
                        try:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                        except Exception:
                            func_name = str(imp.name)

                        # Match with suspicious categories
                        for category, api_list in SUSPICIOUS_API_RULES.items():
                            for target_api in api_list:
                                if func_name == target_api or func_name == f"{target_api}A" or func_name == f"{target_api}W":
                                    if func_name not in suspicious_apis[category]:
                                        suspicious_apis[category].append(func_name)
                                        total_suspicious_count += 1

            # Filter out empty categories
            active_suspicious_apis = {k: v for k, v in suspicious_apis.items() if v}

            return {
                'is_pe': True,
                'architecture': architecture,
                'subsystem': subsystem,
                'compile_time': compile_time_str,
                'is_suspicious_time': is_suspicious_time,
                'is_signed': is_signed,
                'sections': sections,
                'has_suspicious_sections': has_suspicious_sections,
                'detected_packers': sorted(list(detected_packers)),
                'imported_dlls': imported_dlls,
                'suspicious_apis': active_suspicious_apis,
                'total_suspicious_apis': total_suspicious_count
            }
        finally:
            pe.close()
