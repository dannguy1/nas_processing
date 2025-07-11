# 3GPP NAS Log Processing System — Architecture Overview

This document describes the architecture of a robust, extensible system for parsing, extracting, grouping, analyzing, and intelligently interpreting 3GPP NAS logs, empowering field technicians with automation and AI-driven insights.

---

## 1. System Architecture

Modular components:
1. Raw Log Acquisition & Preprocessing
2. Parsing and Field Extraction
3. Data Normalization and Enrichment
4. Logical Grouping and Sessionization
5. AI/ML-Driven Analysis & Troubleshooting
6. User Interaction, Visualization, and Export
7. Extensibility, Testing, and Automation

---

## 2. Component Breakdown

### 2.1. Raw Log Acquisition & Preprocessing
- **Input**: NAS logs from QxDM/QCAT in text format
- **Preprocessing**: Export binary logs as text using vendor tools
- **Validation**: Check log integrity before processing
- **Batch Support**: Versioned storage for traceability

### 2.2. Parsing and Field Extraction
- **Parsing Engine**: Python with regex and stateful parsing
- **Field Extraction**: Extracts timestamp, direction, message type, etc. (see PRD)
- **Configuration**: Field mappings in a config file
- **Output**: Normalized CSV (`nas_events_expanded.csv`)

### 2.3. Data Normalization and Enrichment
- **Normalization**: Standardizes formats (e.g., timestamps, IPs)
- **Enrichment**: Derives fields like `procedure`, `session_key`
- **Validation**: Flags inconsistencies/missing data

### 2.4. Logical Grouping and Sessionization
- **Grouping Strategies**:
  - By Procedure, Message Type, Session, Direction, Time Window
  - Handles overlapping/incomplete sessions
- **Output**: Named CSVs (e.g., `procedure_Attach.csv`)

### 2.5. AI/ML-Driven Analysis & Troubleshooting
- **Frameworks**: TensorFlow, Scikit-learn
- **Anomaly Detection**: Unsupervised (e.g., Isolation Forest)
- **Root Cause Analysis**: Supervised ML + rules
- **Recommendations**: Knowledge base mapping
- **NLP**: Summaries via LLM integration
- **Feedback Loop**: Continuous improvement

### 2.6. User Interaction, Visualization, and Export
- **Interface**: CLI and web dashboard (mobile-friendly)
- **Visualization**: Plots with Plotly/Matplotlib
- **Export**: CSV, JSON, Excel, database

### 2.7. Extensibility, Testing, and Automation
- **Modularity**: Easy addition of features
- **Testing**: Unit/integration tests
- **Automation**: Batch processing via APIs
- **Monitoring**: Performance logging

---

## 3. Data Flow Diagram

```
Raw Logs → Validation → Parsing → Normalization → Grouping → AI Analysis → Visualization/Export
```

---

## 4. Component Interaction Diagram

```
[User] ↔ [Dashboard/CLI] ↔ [Main Driver] ↔ [Parser | Grouper | AI Engine]
```

---

## 5. Error Handling and Recovery
- Skip malformed lines with logging
- Retry mechanisms for transient failures
- Backup of raw logs

---

## 6. Scalability and Performance
- Parallel processing for large logs
- Optimized memory usage for >100MB logs

---

## 7. Workflow Example

```sh
python3 main.py --step parse --input raw_log.txt --output nas_events_expanded.csv
python3 main.py --step group --input nas_events_expanded.csv --group procedure session --output grouped/
python3 main.py --step analyze --input grouped/ --output ai_results/
```

---

## 8. Directory Structure

```
wpp/
├── raw_logs/
├── src/
│   ├── main.py
│   ├── parser.py
│   ├── grouping.py
│   ├── ai_analysis.py
│   ├── config/
│   │   └── field_map.yaml
│   └── tests/
├── grouped/
├── ai_results/
├── logs/
│   └── system.log
└── docs/
```

---

## 9. Advanced Features (Roadmap)
- Protocol State Machine
- Real-Time Streaming
- Ticketing/OSS Integration
- Interactive Web Interface

---

## 10. References
- 3GPP TS 24.301, TS 24.008
- QxDM/QCAT Guides
- [PRD](./3GPP Log Processing - PRD.md)