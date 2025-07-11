#!/bin/bash

# NAS Log Analysis Workflow - Demonstration Script
# This script demonstrates the complete analysis workflow using the sample log file

set -e  # Exit on any error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}$1${NC}"
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if sample log exists
SAMPLE_LOG="docs/NAS_speed_test_06-02.15-53-27-127.txt"
if [[ ! -f "$SAMPLE_LOG" ]]; then
    echo "❌ Sample log file not found: $SAMPLE_LOG"
    exit 1
fi

print_header "🚀 NAS Log Analysis Workflow - Demonstration"
echo ""

print_status "This demonstration will show the complete analysis workflow using the sample log file."
echo ""

# Step 1: Basic analysis
print_header "Step 1: Basic Analysis (Default Settings)"
print_status "Running complete analysis with default settings..."
echo ""

./run_analysis.sh "$SAMPLE_LOG" --output-dir "demo_results/basic"

echo ""
print_status "✅ Basic analysis completed!"
echo ""

# Step 2: Advanced analysis with custom settings
print_header "Step 2: Advanced Analysis (Custom Settings)"
print_status "Running analysis with custom grouping and formats..."
echo ""

./run_analysis.sh "$SAMPLE_LOG" \
  --output-dir "demo_results/advanced" \
  --group-by procedure,direction,session \
  --formats csv,json,html,pdf \
  --verbose

echo ""
print_status "✅ Advanced analysis completed!"
echo ""

# Step 3: Minimal analysis (no visualizations)
print_header "Step 3: Minimal Analysis (No Visualizations)"
print_status "Running minimal analysis without visualizations..."
echo ""

./run_analysis.sh "$SAMPLE_LOG" \
  --output-dir "demo_results/minimal" \
  --no-sequence \
  --no-timeline \
  --formats csv

echo ""
print_status "✅ Minimal analysis completed!"
echo ""

# Step 4: Show results summary
print_header "Step 4: Results Summary"
echo ""

print_status "Generated output directories:"
echo "  📁 demo_results/basic/     - Basic analysis with default settings"
echo "  📁 demo_results/advanced/  - Advanced analysis with custom settings"
echo "  📁 demo_results/minimal/   - Minimal analysis without visualizations"
echo ""

print_status "Key files generated:"
echo "  📄 *_parsed.csv           - Parsed structured data"
echo "  📁 grouped/               - Grouped analysis files"
echo "  📁 analysis/              - Advanced analysis results"
echo "  📄 analysis_summary.json  - Complete workflow summary"
echo ""

print_status "Visualizations (in advanced analysis):"
echo "  🌐 sequence_diagram.html  - Interactive sequence diagram"
echo "  📈 timeline.html          - Interactive timeline"
echo "  📊 detailed_timeline.html - Detailed timeline analysis"
echo ""

print_header "🎉 Demonstration Completed Successfully!"
echo ""
print_status "You can now explore the generated results in the demo_results/ directories."
print_status "Each directory contains a complete analysis workflow output."
echo ""
print_status "To analyze your own logs, use:"
echo "  ./run_analysis.sh your_log_file.txt"
echo ""
print_status "For more options, see:"
echo "  ./run_analysis.sh --help"
echo "  python3 run_complete_analysis.py --help"
echo "" 