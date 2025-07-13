#!/bin/bash

# Example: NAS Log Analysis with Comprehensive Logging
# This script demonstrates the logging capabilities of the analysis workflow

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}$1${NC}"
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Check if sample log exists
SAMPLE_LOG="docs/NAS_speed_test_06-02.15-53-27-127.txt"
if [[ ! -f "$SAMPLE_LOG" ]]; then
    echo "❌ Sample log file not found: $SAMPLE_LOG"
    exit 1
fi

print_header "🔍 NAS Log Analysis - Logging Demonstration"
echo ""

print_status "This demonstration shows different logging options and their outputs."
echo ""

# Example 1: Basic analysis with default logging
print_header "Example 1: Basic Analysis with Default Logging"
print_status "Running analysis with default logging (run_log.json will be generated)..."
echo ""

python3 run_analysis.py "$SAMPLE_LOG" \
  --output-dir "logging_demo/basic" \
  --verbose

echo ""
print_status "✅ Basic analysis completed with logging!"
echo ""

# Example 2: Analysis with custom log file
print_header "Example 2: Analysis with Custom Log File"
print_status "Running analysis with custom log file..."
echo ""

python3 run_analysis.py "$SAMPLE_LOG" \
  --output-dir "logging_demo/custom_log" \
  --log-file "logs/custom_analysis.log" \
  --verbose

echo ""
print_status "✅ Analysis completed with custom log file!"
echo ""

# Example 3: Analysis without run logging (faster)
print_header "Example 3: Analysis Without Run Logging (Faster)"
print_status "Running analysis without run log generation..."
echo ""

python3 run_analysis.py "$SAMPLE_LOG" \
  --output-dir "logging_demo/no_log" \
  --verbose

echo ""
print_status "✅ Analysis completed without run logging!"
echo ""

# Example 4: Analyze run logs
print_header "Example 4: Analyzing Run Logs"
print_status "Analyzing run logs from all executions..."
echo ""

python3 analyze_run_logs.py logging_demo/

echo ""
print_status "✅ Run log analysis completed!"
echo ""

# Show file structure
print_header "Generated Files Summary"
echo ""

print_status "Logging demonstration files:"
echo "  📁 logging_demo/basic/          - Basic analysis with run_log.json"
echo "  📁 logging_demo/custom_log/     - Analysis with custom log file"
echo "  📁 logging_demo/no_log/         - Analysis without run logging"
echo "  📄 logs/custom_analysis.log     - Custom log file"
echo ""

print_status "Key logging files:"
echo "  📄 run_log.json                 - Detailed run log (JSON format)"
echo "  📄 analysis_summary.json        - Workflow summary with log stats"
echo "  📄 custom_analysis.log          - Custom log file (if specified)"
echo ""

print_header "🎉 Logging Demonstration Completed!"
echo ""
print_status "You can now explore the different logging outputs:"
echo "  📊 Check run_log.json files for detailed execution tracking"
echo "  📈 Use analyze_run_logs.py to analyze multiple runs"
echo "  🔍 Compare performance between logged and non-logged runs"
echo ""
print_status "To analyze your own logs with logging:"
echo "  python3 run_analysis.py your_log.txt --verbose"
echo "  python3 analyze_run_logs.py your_results_directory/"
echo "" 