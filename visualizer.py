"""
visualizer.py
Generates all visualization plots for the fileless malware detection demo.
Produces: confusion matrix, ROC curves, feature importance, detection dashboard.
"""

import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
from typing import Dict, List


REPORTS_DIR = 'reports'
COLORS = {
    'CRITICAL': '#d32f2f',
    'HIGH':     '#f57c00',
    'MEDIUM':   '#fbc02d',
    'LOW':      '#388e3c',
    'SAFE':     '#1976d2',
    'benign':   '#1976d2',
    'malicious': '#d32f2f',
}
sns.set_theme(style='darkgrid', palette='muted', font_scale=1.1)
plt.rcParams['figure.dpi'] = 120


def ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def plot_confusion_matrix(cm: np.ndarray, model_name: str, save=True) -> str:
    ensure_reports_dir()
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                xticklabels=['Benign', 'Malicious'],
                yticklabels=['Benign', 'Malicious'],
                linewidths=1, linecolor='white')
    ax.set_xlabel('Predicted Label', fontsize=12)
    ax.set_ylabel('True Label', fontsize=12)
    ax.set_title(f'Confusion Matrix — {model_name}', fontsize=13, fontweight='bold')

    # Highlight TP/TN/FP/FN
    tn, fp, fn, tp = cm.ravel()
    ax.text(0.5, -0.12, f'TN={tn}  FP={fp}  FN={fn}  TP={tp}',
            transform=ax.transAxes, ha='center', fontsize=10, color='gray')

    plt.tight_layout()
    path = os.path.join(REPORTS_DIR, f'confusion_matrix_{model_name.replace(" ", "_")}.png')
    if save:
        fig.savefig(path, bbox_inches='tight')
        plt.close(fig)
    return path


def plot_roc_curves(results: Dict, save=True) -> str:
    ensure_reports_dir()
    fig, ax = plt.subplots(figsize=(8, 6))
    colors_cycle = ['#1976d2', '#d32f2f', '#388e3c', '#9c27b0']

    for i, (name, metrics) in enumerate(results.items()):
        if 'fpr' in metrics and 'tpr' in metrics:
            ax.plot(metrics['fpr'], metrics['tpr'],
                    label=f"{name} (AUC={metrics['roc_auc']:.3f})",
                    color=colors_cycle[i % len(colors_cycle)], lw=2)

    ax.plot([0, 1], [0, 1], 'k--', lw=1.5, label='Random Baseline')
    ax.fill_between([0, 1], [0, 0], [1, 1], alpha=0.03, color='gray')
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.02])
    ax.set_xlabel('False Positive Rate', fontsize=12)
    ax.set_ylabel('True Positive Rate (Recall)', fontsize=12)
    ax.set_title('ROC Curves — Model Comparison', fontsize=13, fontweight='bold')
    ax.legend(loc='lower right', fontsize=10)
    ax.grid(True, alpha=0.4)

    plt.tight_layout()
    path = os.path.join(REPORTS_DIR, 'roc_curves.png')
    if save:
        fig.savefig(path, bbox_inches='tight')
        plt.close(fig)
    return path


def plot_model_comparison(results: Dict, save=True) -> str:
    ensure_reports_dir()
    metrics_to_plot = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
    labels = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC']

    model_names = list(results.keys())
    x = np.arange(len(metrics_to_plot))
    width = 0.8 / len(model_names)
    bar_colors = ['#1976d2', '#d32f2f', '#388e3c', '#9c27b0']

    fig, ax = plt.subplots(figsize=(12, 6))
    for i, (name, metrics) in enumerate(results.items()):
        values = [metrics.get(m, 0) for m in metrics_to_plot]
        bars = ax.bar(x + i * width, values, width, label=name,
                      color=bar_colors[i % len(bar_colors)], alpha=0.85)
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.005,
                    f'{val:.3f}', ha='center', va='bottom', fontsize=8)

    ax.set_xlabel('Metric', fontsize=12)
    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('Model Performance Comparison', fontsize=13, fontweight='bold')
    ax.set_xticks(x + width * (len(model_names) - 1) / 2)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.15)
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.4)

    plt.tight_layout()
    path = os.path.join(REPORTS_DIR, 'model_comparison.png')
    if save:
        fig.savefig(path, bbox_inches='tight')
        plt.close(fig)
    return path


def plot_feature_importance(fi_df: pd.DataFrame, top_n=15, labels_map: Dict = None, save=True) -> str:
    ensure_reports_dir()
    top = fi_df.head(top_n).copy()
    if labels_map:
        top['feature'] = top['feature'].map(lambda f: labels_map.get(f, f))

    fig, ax = plt.subplots(figsize=(10, 7))
    bars = ax.barh(top['feature'][::-1], top['importance'][::-1],
                   color=sns.color_palette('coolwarm', len(top))[::-1])
    ax.set_xlabel('Importance Score', fontsize=12)
    ax.set_title(f'Top {top_n} Feature Importances (Random Forest)', fontsize=13, fontweight='bold')
    ax.grid(axis='x', alpha=0.4)

    for bar, val in zip(bars, top['importance'][::-1]):
        ax.text(bar.get_width() + 0.001, bar.get_y() + bar.get_height() / 2,
                f'{val:.4f}', va='center', fontsize=9)

    plt.tight_layout()
    path = os.path.join(REPORTS_DIR, 'feature_importance.png')
    if save:
        fig.savefig(path, bbox_inches='tight')
        plt.close(fig)
    return path


def plot_detection_dashboard(results_list, summary: Dict, save=True) -> str:
    """Master dashboard: risk distribution + detection timeline + anomaly scatter."""
    ensure_reports_dir()
    from src.hybrid_detector import RiskLevel

    fig = plt.figure(figsize=(16, 10))
    fig.suptitle('Fileless Malware Detection Dashboard\nIntelligent RAM Analysis System',
                 fontsize=15, fontweight='bold', y=0.98)

    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.4, wspace=0.35)

    # ── Panel 1: Risk Distribution Pie ──────────────────────────────────────
    ax1 = fig.add_subplot(gs[0, 0])
    risk_dist = summary.get('risk_distribution', {})
    risk_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']
    risk_labels = [r for r in risk_order if risk_dist.get(r, 0) > 0]
    risk_vals = [risk_dist.get(r, 0) for r in risk_labels]
    colors_pie = [COLORS.get(r, '#999999') for r in risk_labels]
    wedges, texts, autotexts = ax1.pie(
        risk_vals, labels=risk_labels, colors=colors_pie,
        autopct='%1.1f%%', startangle=140,
        textprops={'fontsize': 9},
    )
    for at in autotexts:
        at.set_fontsize(8)
    ax1.set_title('Process Risk Distribution', fontweight='bold', fontsize=11)

    # ── Panel 2: Detection Summary Bar ──────────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 1])
    cats = ['Total\nProcesses', 'Malicious\nDetected', 'Benign\nProcesses']
    vals = [summary['total_processes'], summary['malicious_detected'], summary['benign']]
    bar_cols = ['#546e7a', '#d32f2f', '#1976d2']
    bars = ax2.bar(cats, vals, color=bar_cols, width=0.5, alpha=0.9)
    for bar, v in zip(bars, vals):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                 str(v), ha='center', fontweight='bold', fontsize=11)
    ax2.set_ylabel('Count', fontsize=10)
    ax2.set_title('Detection Summary', fontweight='bold', fontsize=11)
    ax2.grid(axis='y', alpha=0.4)

    # ── Panel 3: Top YARA Rules ──────────────────────────────────────────────
    ax3 = fig.add_subplot(gs[0, 2])
    top_rules = summary.get('top_yara_rules', [])
    if top_rules:
        rule_names = [r[0].replace('_', '\n') for r in top_rules]
        rule_counts = [r[1] for r in top_rules]
        ax3.barh(rule_names[::-1], rule_counts[::-1], color='#f57c00', alpha=0.85)
        ax3.set_xlabel('Hit Count', fontsize=10)
    ax3.set_title('Top YARA Rule Triggers', fontweight='bold', fontsize=11)
    ax3.grid(axis='x', alpha=0.4)

    # ── Panel 4: ML Score Distribution ──────────────────────────────────────
    ax4 = fig.add_subplot(gs[1, 0])
    benign_scores = [r.ml_probability for r in results_list if not r.is_malicious]
    malicious_scores = [r.ml_probability for r in results_list if r.is_malicious]
    if benign_scores:
        ax4.hist(benign_scores, bins=30, alpha=0.7, color='#1976d2', label='Benign', density=True)
    if malicious_scores:
        ax4.hist(malicious_scores, bins=30, alpha=0.7, color='#d32f2f', label='Malicious', density=True)
    ax4.axvline(0.5, color='orange', linestyle='--', lw=2, label='Decision Boundary')
    ax4.set_xlabel('ML Maliciousness Probability', fontsize=10)
    ax4.set_ylabel('Density', fontsize=10)
    ax4.set_title('ML Score Distribution', fontweight='bold', fontsize=11)
    ax4.legend(fontsize=9)

    # ── Panel 5: Hybrid Score vs Memory Anomaly Scatter ─────────────────────
    ax5 = fig.add_subplot(gs[1, 1])
    hs = [r.hybrid_score for r in results_list]
    labels_bin = [r.is_malicious for r in results_list]
    yara_hits_list = [r.yara_hits for r in results_list]

    scatter_colors = [COLORS['malicious'] if lab else COLORS['benign'] for lab in labels_bin]
    sizes = [30 + yh * 20 for yh in yara_hits_list]

    ax5.scatter(range(len(hs)), hs, c=scatter_colors, alpha=0.5, s=sizes, linewidths=0)
    ax5.axhline(0.5, color='orange', linestyle='--', lw=2, label='Threshold (0.5)')
    ax5.set_xlabel('Process Index', fontsize=10)
    ax5.set_ylabel('Hybrid Detection Score', fontsize=10)
    ax5.set_title('Hybrid Score per Process\n(size = YARA hits)', fontweight='bold', fontsize=11)
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=COLORS['malicious'], label='Malicious'),
                       Patch(facecolor=COLORS['benign'], label='Benign')]
    ax5.legend(handles=legend_elements, fontsize=9)

    # ── Panel 6: Attack Type Breakdown ──────────────────────────────────────
    ax6 = fig.add_subplot(gs[1, 2])
    attack_types = {}
    for r in results_list:
        if r.is_malicious:
            for ind in r.attack_indicators:
                if not ind.startswith('YARA:'):
                    attack_types[ind] = attack_types.get(ind, 0) + 1

    if attack_types:
        top_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:6]
        names = [a[0][:25] + ('...' if len(a[0]) > 25 else '') for a in top_attacks]
        counts = [a[1] for a in top_attacks]
        ax6.barh(names[::-1], counts[::-1], color='#7b1fa2', alpha=0.85)
        ax6.set_xlabel('Count', fontsize=10)
    ax6.set_title('Attack Technique Distribution', fontweight='bold', fontsize=11)
    ax6.grid(axis='x', alpha=0.4)

    path = os.path.join(REPORTS_DIR, 'detection_dashboard.png')
    if save:
        fig.savefig(path, bbox_inches='tight')
        plt.close(fig)
    return path


def plot_cv_scores(cv_scores: np.ndarray, save=True) -> str:
    ensure_reports_dir()
    fig, ax = plt.subplots(figsize=(7, 4))
    folds = [f'Fold {i+1}' for i in range(len(cv_scores))]
    bars = ax.bar(folds, cv_scores, color='#1976d2', alpha=0.85, width=0.5)
    ax.axhline(cv_scores.mean(), color='#d32f2f', linestyle='--', lw=2,
               label=f'Mean F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}')
    for bar, v in zip(bars, cv_scores):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.002,
                f'{v:.3f}', ha='center', fontsize=10)
    ax.set_ylim(0, 1.1)
    ax.set_ylabel('F1 Score', fontsize=12)
    ax.set_title('5-Fold Cross Validation — Random Forest', fontsize=13, fontweight='bold')
    ax.legend(fontsize=11)
    ax.grid(axis='y', alpha=0.4)
    plt.tight_layout()
    path = os.path.join(REPORTS_DIR, 'cross_validation.png')
    if save:
        fig.savefig(path, bbox_inches='tight')
        plt.close(fig)
    return path
