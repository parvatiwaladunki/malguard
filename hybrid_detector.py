"""
hybrid_detector.py
Hybrid detection pipeline: combines YARA signature scanning + ML classification.
Mimics the multi-layer detection module described in the system architecture.
"""

import numpy as np
import pandas as pd
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class RiskLevel(Enum):
    SAFE = 'SAFE'
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'


SEVERITY_MAP = {
    'NONE': 0,
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4,
}

SEVERITY_REVERSE = {v: k for k, v in SEVERITY_MAP.items()}


@dataclass
class DetectionResult:
    process_name: str
    pid: int
    ml_probability: float
    ml_label: str
    yara_hits: int
    yara_score: int
    yara_max_severity: str
    matched_rules: List[str]
    hybrid_score: float
    risk_level: RiskLevel
    is_malicious: bool
    attack_indicators: List[str] = field(default_factory=list)
    recommendation: str = ''


class HybridDetector:
    """
    Multi-layer fileless malware detector.
    Layer 1: YARA signature scanning
    Layer 2: ML-based behavioral classification
    Layer 3: Ensemble decision fusion
    """

    def __init__(self, model_bundle, yara_engine, ml_weight=0.6, yara_weight=0.4):
        self.model_bundle = model_bundle
        self.yara_engine = yara_engine
        self.ml_weight = ml_weight
        self.yara_weight = yara_weight

    def _get_yara_probability(self, yara_result: Dict) -> float:
        """Normalize YARA score to [0, 1] probability-like value."""
        max_possible_score = 5 * 10  # CRITICAL (5) * 10 rules
        raw_score = yara_result.get('total_score', 0)
        return min(raw_score / max_possible_score, 1.0)

    def _get_attack_indicators(self, row: Dict, yara_result: Dict) -> List[str]:
        indicators = []
        if row.get('process_hollowing'):
            indicators.append('Process Hollowing Detected')
        if row.get('dll_injection'):
            indicators.append('DLL Injection Detected')
        if row.get('reflective_load'):
            indicators.append('Reflective DLL Loading')
        if row.get('encoded_powershell'):
            indicators.append('Encoded PowerShell Command')
        if row.get('lolbin_usage'):
            indicators.append('Living-off-the-Land Binary Abuse')
        if row.get('wmi_execution'):
            indicators.append('WMI-Based Execution')
        if row.get('suspicious_parent'):
            indicators.append('Suspicious Parent Process')
        if row.get('heap_executable'):
            indicators.append('Executable Heap Region (W^X violation)')
        if row.get('writable_exec_sections', 0) > 0:
            indicators.append(f"Writable+Executable Memory Sections ({row['writable_exec_sections']})")
        if row.get('unusual_thread_start'):
            indicators.append('Thread Starting in Unusual Memory Region')
        for rule in yara_result.get('matched_rules', []):
            if rule not in indicators:
                indicators.append(f'YARA: {rule}')
        return indicators

    def _get_recommendation(self, risk_level: RiskLevel, indicators: List[str]) -> str:
        if risk_level == RiskLevel.CRITICAL:
            return 'IMMEDIATE ACTION REQUIRED: Isolate endpoint, terminate process, capture full memory dump for forensic analysis.'
        elif risk_level == RiskLevel.HIGH:
            return 'ALERT SOC TEAM: Quarantine process, review parent process tree, collect evidence for incident response.'
        elif risk_level == RiskLevel.MEDIUM:
            return 'INVESTIGATE: Review process behavior, check network connections, escalate if suspicious activity continues.'
        elif risk_level == RiskLevel.LOW:
            return 'MONITOR: Log process activity, apply additional behavioral monitoring rules.'
        else:
            return 'No action required. Process appears benign.'

    def _compute_risk_level(self, hybrid_score: float, yara_max_sev: str) -> RiskLevel:
        sev_code = SEVERITY_MAP.get(yara_max_sev, 0)
        if hybrid_score >= 0.85 or sev_code >= 4:
            return RiskLevel.CRITICAL
        elif hybrid_score >= 0.65 or sev_code >= 3:
            return RiskLevel.HIGH
        elif hybrid_score >= 0.40 or sev_code >= 2:
            return RiskLevel.MEDIUM
        elif hybrid_score >= 0.20 or sev_code >= 1:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE

    def detect(self, process_row: Dict) -> DetectionResult:
        """Run full hybrid detection on a single process."""
        try:
            from src.feature_extractor import engineer_features, FEATURE_COLUMNS
        except ImportError:
            from feature_extractor import engineer_features, FEATURE_COLUMNS

        process_name = str(process_row.get('process_name', 'unknown'))
        pid = int(process_row.get('pid', 0))
        cmd_line = str(process_row.get('cmd_line', ''))

        # Layer 1: YARA scan
        yara_result = self.yara_engine.scan_process(process_name, cmd_line)
        yara_prob = self._get_yara_probability(yara_result)

        # Layer 2: ML classification
        df = pd.DataFrame([process_row])
        df = engineer_features(df)
        feature_names = self.model_bundle['feature_names']
        available = [f for f in feature_names if f in df.columns]
        X = df[available].fillna(0)

        model = self.model_bundle['model']
        ml_prob = float(model.predict_proba(X)[0][1])

        # Layer 3: Weighted fusion
        hybrid_score = round(
            self.ml_weight * ml_prob + self.yara_weight * yara_prob, 4
        )

        is_malicious = hybrid_score >= 0.5
        ml_label = 'MALICIOUS' if ml_prob >= 0.5 else 'BENIGN'

        risk_level = self._compute_risk_level(hybrid_score, yara_result.get('max_severity', 'NONE'))

        indicators = self._get_attack_indicators(process_row, yara_result)
        recommendation = self._get_recommendation(risk_level, indicators)

        return DetectionResult(
            process_name=process_name,
            pid=pid,
            ml_probability=round(ml_prob, 4),
            ml_label=ml_label,
            yara_hits=yara_result.get('hit_count', 0),
            yara_score=yara_result.get('total_score', 0),
            yara_max_severity=yara_result.get('max_severity', 'NONE'),
            matched_rules=yara_result.get('matched_rules', []),
            hybrid_score=hybrid_score,
            risk_level=risk_level,
            is_malicious=is_malicious,
            attack_indicators=indicators,
            recommendation=recommendation,
        )

    def batch_detect(self, df: pd.DataFrame) -> List[DetectionResult]:
        """Run detection on all rows of a dataframe."""
        results = []
        for _, row in df.iterrows():
            result = self.detect(row.to_dict())
            results.append(result)
        return results

    def summarize_results(self, results: List[DetectionResult]) -> Dict:
        """Summarize batch detection results."""
        total = len(results)
        malicious = sum(1 for r in results if r.is_malicious)
        risk_counts = {}
        for r in results:
            risk_counts[r.risk_level.value] = risk_counts.get(r.risk_level.value, 0) + 1

        all_rules = {}
        for r in results:
            for rule in r.matched_rules:
                all_rules[rule] = all_rules.get(rule, 0) + 1

        top_threats = sorted(
            [r for r in results if r.is_malicious],
            key=lambda x: x.hybrid_score,
            reverse=True
        )[:10]

        return {
            'total_processes': total,
            'malicious_detected': malicious,
            'benign': total - malicious,
            'detection_rate': round(malicious / total, 4) if total > 0 else 0,
            'risk_distribution': risk_counts,
            'top_yara_rules': sorted(all_rules.items(), key=lambda x: x[1], reverse=True)[:5],
            'top_threats': top_threats,
            'avg_hybrid_score_malicious': round(
                np.mean([r.hybrid_score for r in results if r.is_malicious]), 4
            ) if malicious > 0 else 0.0,
        }
