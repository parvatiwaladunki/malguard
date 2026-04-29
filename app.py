"""
app.py — Flask web dashboard for Fileless Malware Detection System
"""

import sys, os, json, time, random, datetime, io, csv
import warnings
import numpy as np
warnings.filterwarnings('ignore')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, jsonify, request, Response, send_file
from dataclasses import asdict
from fpdf import FPDF

from src.data_generator import generate_benign_sample, generate_malicious_sample
from src.ml_models import load_model
from src.yara_engine import YaraEngine
from src.hybrid_detector import HybridDetector

app = Flask(__name__)

# ─── Global state ─────────────────────────────────────────────────────────────
_detector            = None
_model_metrics       = None
_feature_names       = None
_feature_importances = None
_cached_scan         = None   # Results of the last scan (pre-loaded on startup)
_scan_history        = None   # Simulated 24h hourly data


# ─── Startup helpers ──────────────────────────────────────────────────────────

def _load():
    global _detector, _model_metrics, _feature_names, _feature_importances
    global _cached_scan, _scan_history

    bundle = load_model()
    yara   = YaraEngine()
    _detector = HybridDetector(bundle, yara)

    _model_metrics = dict(bundle.get('metrics', {}))
    _model_metrics['model_name']     = bundle.get('model_name', 'Unknown')
    _model_metrics['feature_count']  = len(bundle.get('feature_names', []))

    _feature_names       = bundle.get('feature_names', [])
    rf = bundle['model'].steps[-1][1]
    if hasattr(rf, 'feature_importances_'):
        _feature_importances = rf.feature_importances_.tolist()

    _cached_scan  = _run_scan(n=60, mal_ratio=0.25, seed=42)
    _scan_history = _generate_history()


def _result_to_dict(result):
    d = asdict(result)
    d['risk_level'] = result.risk_level.value
    return d


def _run_scan(n=60, mal_ratio=0.25, seed=None):
    rng    = np.random.default_rng(seed)
    n_mal  = max(1, int(n * mal_ratio))
    n_ben  = n - n_mal
    procs  = (
        [generate_benign_sample(rng)    for _ in range(n_ben)] +
        [generate_malicious_sample(rng) for _ in range(n_mal)]
    )
    py_rng = random.Random(seed if seed else 0)
    py_rng.shuffle(procs)

    results = [_result_to_dict(_detector.detect(p)) for p in procs]
    return {'results': results, 'summary': _build_summary(results),
            'scanned_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}


def _build_summary(results):
    malicious = [r for r in results if r['is_malicious']]
    risk_dist = {'SAFE': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for r in results:
        risk_dist[r['risk_level']] += 1

    rule_counts = {}
    for r in results:
        for rule in r['matched_rules']:
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    indicator_counts = {}
    for r in results:
        for ind in r['attack_indicators']:
            key = ind.split('(')[0].strip()          # drop "(N)" suffix
            indicator_counts[key] = indicator_counts.get(key, 0) + 1
    top_indicators = sorted(indicator_counts.items(), key=lambda x: x[1], reverse=True)[:12]

    return {
        'total':           len(results),
        'malicious':       len(malicious),
        'benign':          len(results) - len(malicious),
        'critical':        risk_dist['CRITICAL'],
        'high':            risk_dist['HIGH'],
        'detection_rate':  round(len(malicious) / len(results) * 100, 1) if results else 0,
        'risk_distribution': risk_dist,
        'top_yara_rules':  [{'rule': r, 'count': c} for r, c in top_rules],
        'top_indicators':  [{'indicator': k, 'count': v} for k, v in top_indicators],
        'avg_mal_score':   round(sum(r['hybrid_score'] for r in malicious) / len(malicious), 4) if malicious else 0,
        'total_yara_hits': sum(r['yara_hits'] for r in results),
    }


def _generate_history(n_hours=24):
    """Simulate 24 hours of hourly scan telemetry for the timeline chart."""
    rng = np.random.default_rng(77)
    history = []
    now = datetime.datetime.now()
    for i in range(n_hours, 0, -1):
        t    = now - datetime.timedelta(hours=i)
        hour = t.hour
        mult  = 1.7 if 9 <= hour <= 17 else (0.4 if 0 <= hour <= 5 else 0.9)
        total = int(rng.integers(14, 38) * mult)
        spike = rng.random() < 0.12
        rate  = rng.uniform(0.38, 0.58) if spike else rng.uniform(0.08, 0.26)
        mal   = max(0, int(total * rate))
        history.append({
            'time':           t.strftime('%H:%M'),
            'total':          total,
            'malicious':      mal,
            'benign':         total - mal,
            'detection_rate': round(mal / total * 100, 1) if total else 0,
        })
    return history


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/dashboard')
def dashboard_data():
    fi = []
    if _feature_importances and _feature_names:
        pairs = sorted(zip(_feature_names, _feature_importances),
                       key=lambda x: x[1], reverse=True)[:15]
        fi = [{'feature': f, 'importance': round(v, 4)} for f, v in pairs]
    return jsonify({
        'scan':              _cached_scan,
        'history':           _scan_history,
        'feature_importance': fi,
        'model_metrics':     _model_metrics or {},
    })


@app.route('/api/scan/stream')
def scan_stream():
    """SSE — streams one DetectionResult event per process, then a summary."""
    n         = int(request.args.get('count', 60))
    mal_ratio = float(request.args.get('malicious_ratio', 0.25))
    delay     = float(request.args.get('delay', 0.055))

    def generate():
        global _cached_scan
        rng   = np.random.default_rng()
        n_mal = max(1, int(n * mal_ratio))
        n_ben = n - n_mal
        procs = (
            [generate_benign_sample(rng)    for _ in range(n_ben)] +
            [generate_malicious_sample(rng) for _ in range(n_mal)]
        )
        random.shuffle(procs)

        results = []
        for i, proc in enumerate(procs):
            d = _result_to_dict(_detector.detect(proc))
            results.append(d)
            yield f"data: {json.dumps({'type':'result','index':i+1,'total':n,'result':d})}\n\n"
            time.sleep(delay)

        summary = _build_summary(results)
        _cached_scan = {
            'results': results, 'summary': summary,
            'scanned_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        yield f"data: {json.dumps({'type':'summary','summary':summary})}\n\n"
        yield f"data: {json.dumps({'type':'done'})}\n\n"

    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no',
    })


@app.route('/api/report/csv')
def report_csv():
    """Download scan results as CSV."""
    if not _cached_scan:
        return jsonify({'error': 'No scan data'}), 404

    results = _cached_scan['results']
    cols = ['process_name', 'pid', 'risk_level', 'hybrid_score', 'ml_probability',
            'ml_label', 'yara_hits', 'yara_score', 'yara_max_severity', 'is_malicious',
            'matched_rules', 'attack_indicators', 'recommendation']

    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction='ignore')
    w.writeheader()
    for r in results:
        row = {k: r.get(k, '') for k in cols}
        row['matched_rules']    = '; '.join(r.get('matched_rules', []))
        row['attack_indicators'] = '; '.join(r.get('attack_indicators', []))
        w.writerow(row)

    fname = f"malguard_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{fname}"'}
    )


@app.route('/api/report/pdf')
def report_pdf():
    """Generate and download a full PDF scan report."""
    if not _cached_scan:
        return jsonify({'error': 'No scan data'}), 404

    scan = _cached_scan
    s    = scan['summary']
    results = scan['results']
    scanned_at = scan.get('scanned_at', 'Unknown')

    # ── Feature importance ──────────────────────────────────────────────────
    fi = []
    if _feature_importances and _feature_names:
        pairs = sorted(zip(_feature_names, _feature_importances),
                       key=lambda x: x[1], reverse=True)[:10]
        fi = [(f, round(v * 100, 1)) for f, v in pairs]

    # ── Build PDF ───────────────────────────────────────────────────────────
    def clean(text):
        t = str(text)
        t = t.replace("—", "-").replace("–", "-").replace("‘", "’").replace("’", "’")
        return t.encode("latin-1", "replace").decode("latin-1")

    class Report(FPDF):
        def header(self):
            self.set_font('Helvetica', 'B', 9)
            self.set_text_color(80, 80, 80)
            self.cell(0, 8, 'MalGuard - Fileless Malware Detection Report', align='L')
            self.set_text_color(150, 150, 150)
            self.cell(0, 8, f'Confidential | {scanned_at}', align='R')
            self.ln(2)
            self.set_draw_color(230, 230, 230)
            self.set_line_width(0.3)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(4)

        def footer(self):
            self.set_y(-13)
            self.set_font('Helvetica', '', 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f'Page {self.page_no()} | Generated by MalGuard SOC Dashboard', align='C')

    pdf = Report()
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_margins(14, 16, 14)
    pdf.add_page()

    # ── Title block ─────────────────────────────────────────────────────────
    pdf.set_font('Helvetica', 'B', 22)
    pdf.set_text_color(15, 15, 15)
    pdf.cell(0, 10, 'Fileless Malware Detection', ln=True)
    pdf.set_font('Helvetica', '', 13)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 7, 'Memory Process Analysis - SOC Threat Report', ln=True)
    pdf.ln(3)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(130, 130, 130)
    pdf.cell(0, 6, clean(f'Scan completed: {scanned_at}  |  Model: {_model_metrics.get("model_name","Random Forest")}  |  Engine: YARA + ML Hybrid'), ln=True)
    pdf.ln(6)

    # ── Horizontal rule ─────────────────────────────────────────────────────
    def hline():
        pdf.set_draw_color(220, 220, 220)
        pdf.set_line_width(0.3)
        pdf.line(14, pdf.get_y(), 196, pdf.get_y())
        pdf.ln(5)

    def section_title(title):
        pdf.ln(2)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(20, 20, 20)
        pdf.set_fill_color(245, 247, 250)
        pdf.cell(0, 8, f'  {title}', ln=True, fill=True)
        pdf.ln(3)

    def kv_row(label, value, color=None):
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(55, 6, clean(label))
        if color:
            pdf.set_text_color(*color)
        else:
            pdf.set_text_color(20, 20, 20)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 6, clean(str(value)), ln=True)

    # ── Executive Summary ───────────────────────────────────────────────────
    section_title('Executive Summary')

    # 2-column KPI layout
    kpis = [
        ('Total Processes Scanned', s['total']),
        ('Threats Detected',        s['malicious']),
        ('Clean Processes',         s['benign']),
        ('Detection Rate',          f"{s['detection_rate']}%"),
        ('Critical Alerts',         s['critical']),
        ('High-Risk Alerts',        s['high']),
        ('Avg Threat Score',        s['avg_mal_score']),
        ('Total YARA Hits',         s['total_yara_hits']),
    ]
    col_w = 88
    pdf.set_font('Helvetica', '', 9)
    for i in range(0, len(kpis), 2):
        y = pdf.get_y()
        # left
        pdf.set_xy(14, y)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(38, 6, kpis[i][0])
        pdf.set_text_color(20, 20, 20)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(col_w - 38, 6, str(kpis[i][1]))
        # right (if exists)
        if i + 1 < len(kpis):
            pdf.set_xy(14 + col_w, y)
            pdf.set_font('Helvetica', '', 9)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(38, 6, kpis[i+1][0])
            pdf.set_text_color(20, 20, 20)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(0, 6, str(kpis[i+1][1]))
        pdf.ln(6)
    pdf.ln(2)

    # ── Risk Distribution ───────────────────────────────────────────────────
    section_title('Risk Distribution')
    RISK_COLORS = {
        'CRITICAL': (220, 50,  50),
        'HIGH':     (240, 120, 40),
        'MEDIUM':   (220, 170, 30),
        'LOW':      (40,  180, 200),
        'SAFE':     (50,  180, 80),
    }
    for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']:
        count = s['risk_distribution'].get(risk, 0)
        pct   = round(count / s['total'] * 100, 1) if s['total'] else 0
        bar_w = max(1, int(pct * 1.2))
        rc    = RISK_COLORS[risk]
        y = pdf.get_y()
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(*rc)
        pdf.cell(22, 5, risk)
        pdf.set_text_color(60, 60, 60)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_fill_color(*rc)
        pdf.rect(36 + 14, y, bar_w, 4, 'F')
        pdf.set_xy(36 + 14 + bar_w + 3, y)
        pdf.cell(0, 5, f'{count}  ({pct}%)', ln=True)
        pdf.ln(1)
    pdf.ln(3)

    # ── Top Threats ─────────────────────────────────────────────────────────
    section_title('Top 10 Detected Threats')
    threats = sorted([r for r in results if r['is_malicious']],
                     key=lambda x: x['hybrid_score'], reverse=True)[:10]

    # Table header
    pdf.set_fill_color(235, 238, 245)
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_text_color(60, 60, 60)
    cols_w = [38, 14, 20, 18, 14, 72]
    headers = ['Process', 'PID', 'Risk', 'Hybrid Score', 'ML Prob', 'YARA Rules / Indicators']
    for w, h in zip(cols_w, headers):
        pdf.cell(w, 6, h, border='B', fill=True)
    pdf.ln()

    pdf.set_font('Helvetica', '', 8)
    for i, r in enumerate(threats):
        fill = i % 2 == 0
        pdf.set_fill_color(252, 252, 255) if fill else pdf.set_fill_color(255, 255, 255)
        rc = RISK_COLORS.get(r['risk_level'], (80, 80, 80))
        pdf.set_text_color(20, 20, 20)
        pdf.cell(cols_w[0], 5.5, clean(r['process_name'][:22]), fill=fill)
        pdf.cell(cols_w[1], 5.5, str(r['pid']), fill=fill)
        pdf.set_text_color(*rc)
        pdf.cell(cols_w[2], 5.5, clean(r['risk_level']), fill=fill)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(cols_w[3], 5.5, f"{r['hybrid_score']:.3f}", fill=fill)
        pdf.cell(cols_w[4], 5.5, f"{r['ml_probability']:.3f}", fill=fill)
        rules = clean(', '.join(r['matched_rules'][:2]).replace('_', ' ')[:50])
        pdf.cell(cols_w[5], 5.5, rules or '-', fill=fill, ln=True)
    pdf.ln(4)

    # ── YARA Rules Fired ────────────────────────────────────────────────────
    section_title('Top YARA Rules Triggered')
    pdf.set_fill_color(235, 238, 245)
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(90, 6, 'Rule', border='B', fill=True)
    pdf.cell(30, 6, 'Triggers', border='B', fill=True)
    pdf.cell(0,  6, 'Bar', border='B', fill=True, ln=True)
    max_count = max((r['count'] for r in s['top_yara_rules']), default=1)
    for i, rule in enumerate(s['top_yara_rules']):
        fill = i % 2 == 0
        pdf.set_fill_color(252, 252, 255) if fill else pdf.set_fill_color(255, 255, 255)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(90, 5.5, clean(rule['rule'].replace('_', ' ')), fill=fill)
        pdf.cell(30, 5.5, str(rule['count']), fill=fill)
        bar_w = max(1, int(rule['count'] / max_count * 60))
        y = pdf.get_y()
        pdf.set_fill_color(240, 120, 40)
        pdf.rect(pdf.get_x(), y + 1, bar_w, 3.5, 'F')
        pdf.set_fill_color(252, 252, 255) if fill else pdf.set_fill_color(255, 255, 255)
        pdf.cell(0, 5.5, '', fill=fill, ln=True)
    pdf.ln(4)

    # ── Attack Indicators ───────────────────────────────────────────────────
    section_title('Attack Technique Indicators')
    pdf.set_fill_color(235, 238, 245)
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(110, 6, 'Indicator', border='B', fill=True)
    pdf.cell(0, 6, 'Count', border='B', fill=True, ln=True)
    for i, ind in enumerate(s['top_indicators']):
        fill = i % 2 == 0
        pdf.set_fill_color(252, 252, 255) if fill else pdf.set_fill_color(255, 255, 255)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(110, 5.5, clean(ind['indicator'][:60]), fill=fill)
        pdf.cell(0, 5.5, str(ind['count']), fill=fill, ln=True)
    pdf.ln(4)

    # ── Model Performance ───────────────────────────────────────────────────
    pdf.add_page()
    section_title('ML Model Performance')
    metric_keys = [
        ('accuracy',           'Accuracy'),
        ('precision',          'Precision'),
        ('recall',             'Recall (TPR)'),
        ('f1',                 'F1 Score'),
        ('roc_auc',            'ROC-AUC'),
        ('false_positive_rate','False Positive Rate'),
    ]
    for k, label in metric_keys:
        if k in _model_metrics:
            val = _model_metrics[k]
            color = (200, 30, 30) if k == 'false_positive_rate' and val > 0.05 else None
            kv_row(label, f"{val*100:.2f}%", color=color)
    kv_row('Model', _model_metrics.get('model_name', 'Random Forest'))
    kv_row('Feature Count', _model_metrics.get('feature_count', '—'))
    kv_row('Detection Engine', 'YARA Rules + Random Forest Hybrid')
    pdf.ln(4)

    # ── Feature Importance ──────────────────────────────────────────────────
    if fi:
        section_title('Top 10 Feature Importances')
        max_fi = fi[0][1]
        for i, (feat, imp) in enumerate(fi):
            fill = i % 2 == 0
            pdf.set_fill_color(252, 252, 255) if fill else pdf.set_fill_color(255, 255, 255)
            pdf.set_font('Helvetica', '', 8)
            pdf.set_text_color(20, 20, 20)
            y = pdf.get_y()
            pdf.cell(80, 5.5, feat, fill=fill)
            bar_w = max(1, int(imp / max_fi * 70))
            pdf.set_fill_color(130, 90, 200)
            pdf.rect(pdf.get_x(), y + 1, bar_w, 3.5, 'F')
            pdf.set_xy(pdf.get_x() + bar_w + 3, y)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 5.5, f'{imp}%', ln=True)
        pdf.ln(4)

    # ── Full Process Table ──────────────────────────────────────────────────
    section_title('Full Process Scan Results')
    pdf.set_fill_color(235, 238, 245)
    pdf.set_font('Helvetica', 'B', 7)
    pdf.set_text_color(60, 60, 60)
    tcols = [38, 14, 20, 19, 18, 14, 12, 47]
    theads = ['Process', 'PID', 'Risk', 'Hybrid Score', 'ML Prob', 'YARA Hits', 'YARA Sev', 'Attack Indicators']
    for w, h in zip(tcols, theads):
        pdf.cell(w, 5.5, h, border='B', fill=True)
    pdf.ln()

    pdf.set_font('Helvetica', '', 7)
    sorted_results = sorted(results, key=lambda x: x['hybrid_score'], reverse=True)
    for i, r in enumerate(sorted_results):
        if pdf.get_y() > 270:
            pdf.add_page()
        fill = i % 2 == 0
        pdf.set_fill_color(252, 252, 255) if fill else pdf.set_fill_color(255, 255, 255)
        rc = RISK_COLORS.get(r['risk_level'], (80, 80, 80))
        pdf.set_text_color(20, 20, 20)
        pdf.cell(tcols[0], 5, clean(r['process_name'][:22]), fill=fill)
        pdf.cell(tcols[1], 5, str(r['pid']), fill=fill)
        pdf.set_text_color(*rc)
        pdf.cell(tcols[2], 5, clean(r['risk_level']), fill=fill)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(tcols[3], 5, f"{r['hybrid_score']:.3f}", fill=fill)
        pdf.cell(tcols[4], 5, f"{r['ml_probability']:.3f}", fill=fill)
        sev_c = RISK_COLORS.get(r['yara_max_severity'], (80, 80, 80))
        pdf.cell(tcols[5], 5, str(r['yara_hits']), fill=fill)
        pdf.set_text_color(*sev_c)
        pdf.cell(tcols[6], 5, clean(r['yara_max_severity'][:6]), fill=fill)
        pdf.set_text_color(80, 80, 80)
        inds = clean('; '.join(r['attack_indicators'][:2])[:44])
        pdf.cell(tcols[7], 5, inds or '-', fill=fill, ln=True)

    buf = io.BytesIO(pdf.output())
    fname = f"malguard_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(buf, mimetype='application/pdf',
                     as_attachment=True, download_name=fname)


if __name__ == '__main__':
    print("Loading model and running initial scan...")
    _load()
    s = _cached_scan['summary']
    print(f"Ready — {s['total']} processes scanned | "
          f"{s['malicious']} threats | {s['critical']} critical")
    print("Dashboard → http://localhost:5000")
    app.run(debug=False, port=5000, threaded=True)
