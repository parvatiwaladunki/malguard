"""
feature_extractor.py
Extracts and engineers features from raw process/memory data for ML classification.
Simulates what would be extracted from Volatility memory forensics output.
"""

import numpy as np
import pandas as pd
from typing import List


FEATURE_COLUMNS = [
    'cmd_line_length',
    'num_threads',
    'num_handles',
    'working_set_mb',
    'private_bytes_mb',
    'session_id',
    'is_signed',
    'num_loaded_dlls',
    'has_network_conn',
    'num_network_conns',
    'writable_exec_sections',
    'private_memory_ratio',
    'heap_executable',
    'vad_count',
    'suspicious_parent',
    'process_hollowing',
    'dll_injection',
    'reflective_load',
    'encoded_powershell',
    'lolbin_usage',
    'wmi_execution',
    'unusual_thread_start',
    'yara_hits',
    'memory_anomaly_score',
    # Engineered features (added below)
    'handles_per_thread',
    'dll_load_ratio',
    'network_density',
    'memory_pressure',
    'behavioral_score',
    'is_lolbin_process',
    'cmd_line_suspicious_length',
]


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add computed/engineered features to the dataframe."""
    df = df.copy()

    # Handles per thread ratio (anomalous if very high or very low for the process count)
    df['handles_per_thread'] = np.where(
        df['num_threads'] > 0,
        df['num_handles'] / df['num_threads'].clip(lower=1),
        0
    ).round(3)

    # DLL load ratio (relative to VAD count - high ratio can indicate injection)
    df['dll_load_ratio'] = np.where(
        df['vad_count'] > 0,
        df['num_loaded_dlls'] / df['vad_count'].clip(lower=1),
        0
    ).round(4)

    # Network density (connections relative to threads)
    df['network_density'] = np.where(
        df['num_threads'] > 0,
        df['num_network_conns'] / df['num_threads'].clip(lower=1),
        0
    ).round(4)

    # Memory pressure (private bytes relative to working set)
    df['memory_pressure'] = np.where(
        df['working_set_mb'] > 0,
        df['private_bytes_mb'] / df['working_set_mb'].clip(lower=0.01),
        0
    ).clip(0, 1).round(4)

    # Behavioral score: aggregate suspicious indicators
    behavioral_cols = [
        'suspicious_parent', 'process_hollowing', 'dll_injection',
        'reflective_load', 'encoded_powershell', 'lolbin_usage',
        'wmi_execution', 'unusual_thread_start', 'heap_executable',
    ]
    weights = [3, 5, 4, 4, 3, 2, 3, 3, 3]
    df['behavioral_score'] = sum(
        df[col] * w for col, w in zip(behavioral_cols, weights)
        if col in df.columns
    )

    # Is the process name a known LOLBin?
    lolbins = {'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
               'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
               'msiexec.exe', 'bitsadmin.exe', 'wmic.exe', 'wmiprvse.exe'}
    if 'process_name' in df.columns:
        df['is_lolbin_process'] = df['process_name'].str.lower().isin(lolbins).astype(int)
    else:
        df['is_lolbin_process'] = 0

    # Command line suspicious length (very long CMD lines are suspicious)
    df['cmd_line_suspicious_length'] = (df['cmd_line_length'] > 150).astype(int)

    return df


def get_feature_matrix(df: pd.DataFrame, target_col: str = 'label'):
    """Returns X (feature matrix) and y (labels) for ML training."""
    df_feat = engineer_features(df)

    available_features = [c for c in FEATURE_COLUMNS if c in df_feat.columns]
    X = df_feat[available_features].fillna(0)
    y = df_feat[target_col] if target_col in df_feat.columns else None

    return X, y, available_features


def get_feature_importance_labels() -> dict:
    """Human-readable descriptions for each feature."""
    return {
        'cmd_line_length': 'Command Line Length',
        'num_threads': 'Thread Count',
        'num_handles': 'Handle Count',
        'working_set_mb': 'Working Set (MB)',
        'private_bytes_mb': 'Private Bytes (MB)',
        'session_id': 'Session ID',
        'is_signed': 'Binary is Signed',
        'num_loaded_dlls': 'Loaded DLL Count',
        'has_network_conn': 'Has Network Connection',
        'num_network_conns': 'Network Connection Count',
        'writable_exec_sections': 'Writable+Executable Sections',
        'private_memory_ratio': 'Private Memory Ratio',
        'heap_executable': 'Heap is Executable',
        'vad_count': 'VAD Region Count',
        'suspicious_parent': 'Suspicious Parent Process',
        'process_hollowing': 'Process Hollowing Detected',
        'dll_injection': 'DLL Injection Detected',
        'reflective_load': 'Reflective DLL Loading',
        'encoded_powershell': 'Encoded PowerShell Command',
        'lolbin_usage': 'LOLBin Usage',
        'wmi_execution': 'WMI-Based Execution',
        'unusual_thread_start': 'Unusual Thread Start Address',
        'yara_hits': 'YARA Rule Hits',
        'memory_anomaly_score': 'Memory Anomaly Score',
        'handles_per_thread': 'Handles per Thread Ratio',
        'dll_load_ratio': 'DLL Load Ratio',
        'network_density': 'Network Density',
        'memory_pressure': 'Memory Pressure',
        'behavioral_score': 'Behavioral Indicator Score',
        'is_lolbin_process': 'Process is LOLBin',
        'cmd_line_suspicious_length': 'Suspicious CMD Length Flag',
    }


if __name__ == '__main__':
    from data_generator import generate_dataset
    df = generate_dataset(n_benign=100, n_malicious=50)
    X, y, feats = get_feature_matrix(df)
    print(f"Feature matrix shape: {X.shape}")
    print(f"Features: {feats}")
    print(f"Class distribution - Benign: {(y==0).sum()}, Malicious: {(y==1).sum()}")
