PROJECT POSTER PRESENTATION

═══════════════════════════════════════════════════════════════════════════════

DAYANANDA SAGAR COLLEGE OF ENGINEERING
Department of Information Science and Engineering
Bangalore – 560 111

═══════════════════════════════════════════════════════════════════════════════

**Title of the Project**

MalGuard — Fileless Malware Detection Dashboard

───────────────────────────────────────────────────────────────────────────────

**Group No.** 17

**Student Names:**
- Meghana Deshmukh
- Mounika T
- Parvati Waladunki
- Puneetha G

**Guided by:** Dr. Deepthi V S
**Designation:** Assistant Professor

═══════════════════════════════════════════════════════════════════════════════

**OBJECTIVE**

Design and implement a hybrid fileless malware detection system using machine 
learning (Random Forest) combined with a YARA rule engine for analyzing process 
memory data. Create a real-time SOC-style web dashboard that detects advanced 
attack techniques including Process Hollowing, DLL Injection, Reflective Loading, 
PowerShell abuse, LOLBins, and WMI execution with high accuracy and provides 
actionable threat intelligence to security operations teams.

═══════════════════════════════════════════════════════════════════════════════

**EXPERIMENTAL DETAILS**

Technology Stack:
  • Backend: Python 3.9+, Flask Web Framework
  • Machine Learning: Scikit-learn (Random Forest, Gradient Boosting, SVM)
  • Detection Engine: YARA-like Rule Engine with 10 signature rules
  • Frontend: HTML5, CSS3, JavaScript for interactive dashboard
  • Data Processing: NumPy, Pandas
  • Export: ReportLab (PDF), CSV export capabilities

Machine Learning Models:
  • Primary: Random Forest Classifier
  • Secondary: Gradient Boosting Classifier
  • Tertiary: Support Vector Machine (SVM)
  • Hybrid Scoring: 60% ML probability + 40% YARA rule detection score

Feature Engineering:
  • Total Features Extracted: 31 memory-based behavioral indicators
  • Data Representation: Synthetic process memory snapshots
  • Dataset Size: 60 process samples (malicious & benign classification)

Detection Capabilities:
  • Process Hollowing Detection
  • DLL Injection Identification
  • Reflective Loading Analysis
  • PowerShell Abuse Detection
  • Living-off-the-Land Binaries (LOLBins) Recognition
  • WMI Execution Monitoring
  • Process Memory Anomaly Detection

═══════════════════════════════════════════════════════════════════════════════

**BACKGROUND/PHOTOS OF THE PROJECT**

[Screenshots and diagrams to be included:]
  • Dashboard Overview: KPI cards, threat timeline, risk distribution
  • Threat Alerts Section: Detected malicious processes with severity
  • Process Analysis Table: Sortable list of 60 scanned processes
  • ML Analytics: Feature importance charts, model metrics
  • System Architecture: Data flow from memory scanning to detection

═══════════════════════════════════════════════════════════════════════════════

**SALIENT FEATURES OF THE PROJECT / METHODOLOGY**

1. Dual Detection Engine
   Combines predictive machine learning models with signature-based YARA rules
   for comprehensive threat detection coverage

2. Real-time SOC Dashboard
   • Live threat feed with severity indicators
   • 24-hour detection timeline visualization
   • KPI summary cards (critical, high, medium, low threats)
   • Risk distribution analytics

3. Advanced Threat Detection
   Identifies 8+ fileless attack techniques with behavioral analysis of process
   memory patterns and system call sequences

4. Hybrid Scoring System
   Intelligent weighting of ML confidence scores and YARA rule matches for
   reduced false positives and false negatives

5. Export Capabilities
   • PDF: Comprehensive analyst reports with summary, threats table, YARA rules,
     and ML metrics
   • CSV: Raw scan data for import into Excel, Google Sheets, or SIEM platforms

6. Live Rescan Feature
   Real-time streaming results for continuous monitoring and threat detection
   updates without system restart

7. Model Transparency & Analytics
   • Feature importance rankings for model interpretability
   • ML performance metrics (precision, recall, F1-score, AUC-ROC)
   • Score distribution analysis and confidence intervals

═══════════════════════════════════════════════════════════════════════════════

**APPLICATIONS OF THE PROJECT**

Security Operations Centers (SOCs)
  Enterprise security teams can deploy MalGuard for real-time detection of
  fileless malware across endpoint infrastructure

Cybersecurity Education & Training
  Educational platform for students and professionals to understand advanced
  malware analysis, machine learning in security, and behavioral detection

Threat Intelligence & Research
  Security researchers analyzing process memory anomalies and developing new
  detection signatures for emerging attack vectors

Enterprise Endpoint Defense
  Critical infrastructure, government organizations, and financial institutions
  can integrate MalGuard into their defense-in-depth strategies

Incident Response & Forensics
  Rapid detection and isolation of Advanced Persistent Threats (APTs) during
  active incident response operations

Compliance & Auditing
  Organizations meeting security compliance requirements (ISO 27001, NIST CSF)
  can leverage MalGuard for threat detection audit trails

═══════════════════════════════════════════════════════════════════════════════

**RESULTS / OUTPUT**

Detection Performance:
  • Hybrid Detection Accuracy: High precision with reduced false positives
  • Processing Speed: Real-time analysis of process memory snapshots
  • Scalability: Capable of scanning 60+ processes simultaneously

Dashboard Metrics & Visualizations:
  ✓ Real-time threat detection with instant alerting
  ✓ Sortable and filterable process analysis table (60 scanned processes)
  ✓ Feature importance rankings for model interpretability
  ✓ Score distribution analysis with statistical summaries
  ✓ 24-hour threat timeline with temporal patterns
  ✓ Risk heatmaps and severity distribution charts

Downloadable Reports:
  • PDF Export: Complete analyst report including:
    - Executive summary with threat overview
    - Detailed threats table with process information
    - YARA rule matches and signatures triggered
    - Machine learning model metrics and performance
    - Recommendations for remediation
  
  • CSV Export: Raw scan data with all 31 features and detection scores
    for further analysis in data analysis tools

System Output Examples:
  • Threat Alerts: Process identification, detection method, confidence score
  • Process Details: Memory characteristics, behavioral flags, risk assessment
  • Model Insights: Top contributing features, prediction confidence, rule matches

═══════════════════════════════════════════════════════════════════════════════

**CONCLUSION**

MalGuard successfully demonstrates a modern, sophisticated approach to 
cybersecurity using hybrid machine learning and signature-based detection 
methodologies. By combining the predictive power of Random Forest classification 
with the precision of YARA rule matching, the system bridges the critical gap 
between traditional antivirus signature detection and advanced behavioral analysis.

The intuitive SOC-style dashboard empowers security teams with actionable 
intelligence for rapid threat identification and response. The comprehensive 
export functionality enables integration with existing security infrastructure 
and compliance reporting processes. MalGuard represents a practical, deployable 
solution for detecting sophisticated fileless malware attacks that traditional 
file-based scanners miss, making it an essential tool for modern cybersecurity 
operations.

═══════════════════════════════════════════════════════════════════════════════
