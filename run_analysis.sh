#!/bin/bash

# Complete NAS Log Analysis Workflow - Shell Wrapper
# This script provides a simple interface to run the complete analysis workflow

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}$1${NC}"
}

# Function to show usage
show_usage() {
    cat << EOF
Complete NAS Log Analysis Workflow

Usage: $0 [options] <log_file>
   or: $0 -i <log_file> [options]

Arguments:
  log_file              Path to input NAS log file

Options:
  -i, --input FILE      Path to input NAS log file
  -o, --output-dir DIR  Output directory (default: output)
  -g, --group-by LIST   Comma-separated grouping criteria (default: procedure,direction)
                        Available: procedure, message_type, session, direction
  -f, --formats LIST    Comma-separated output formats (default: csv,json,html)
                        Available: csv, json, excel, html, pdf
  -v, --verbose         Enable verbose logging
  --no-sequence         Skip sequence diagram generation
  --no-timeline         Skip timeline visualization generation
  --log-file FILE       Save logs to specified file
  --no-log             Skip run log generation
  -h, --help           Show this help message

Examples:
  # Basic usage with default settings
  $0 data/raw_logs/my_log.txt

  # Using input/output options
  $0 -i data/raw_logs/my_log.txt -o results/my_analysis

  # Custom grouping and formats
  $0 -i data/raw_logs/my_log.txt \\
    --group-by procedure,direction,session \\
    --formats csv,json,html,pdf

  # Verbose output with custom directory
  $0 -i data/raw_logs/my_log.txt \\
    --output-dir results/my_analysis \\
    --verbose \\
    --log-file logs/analysis.log

  # Minimal analysis (no visualizations)
  $0 -i data/raw_logs/my_log.txt \\
    --no-sequence \\
    --no-timeline \\
    --formats csv

EOF
}

# Parse command line arguments
INPUT_LOG=""
OUTPUT_DIR=""
GROUP_BY=""
FORMATS=""
VERBOSE=""
NO_SEQUENCE=""
NO_TIMELINE=""
LOG_FILE=""
NO_LOG=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -i|--input)
            INPUT_LOG="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -g|--group-by)
            GROUP_BY="$2"
            shift 2
            ;;
        -f|--formats)
            FORMATS="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE="-v"
            shift
            ;;
        --no-sequence)
            NO_SEQUENCE="--no-sequence-diagram"
            shift
            ;;
        --no-timeline)
            NO_TIMELINE="--no-timeline"
            shift
            ;;
        --log-file)
            LOG_FILE="--log-file $2"
            shift 2
            ;;
        --no-log)
            NO_LOG="--no-log"
            shift
            ;;
        -*)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
        *)
            if [[ -z "$INPUT_LOG" ]]; then
                INPUT_LOG="$1"
            else
                print_error "Multiple input files specified. Only one log file allowed."
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate input
if [[ -z "$INPUT_LOG" ]]; then
    print_error "No input log file specified"
    show_usage
    exit 1
fi

if [[ ! -f "$INPUT_LOG" ]]; then
    print_error "Input file '$INPUT_LOG' not found"
    exit 1
fi

# Set default output directory if not specified
if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="output"
fi

# Build command
CMD="python3 run_complete_analysis.py \"$INPUT_LOG\""

if [[ -n "$OUTPUT_DIR" ]]; then
    CMD="$CMD --output-dir \"$OUTPUT_DIR\""
fi

if [[ -n "$GROUP_BY" ]]; then
    CMD="$CMD --group-by $GROUP_BY"
fi

if [[ -n "$FORMATS" ]]; then
    CMD="$CMD --formats $FORMATS"
fi

if [[ -n "$VERBOSE" ]]; then
    CMD="$CMD $VERBOSE"
fi

if [[ -n "$NO_SEQUENCE" ]]; then
    CMD="$CMD $NO_SEQUENCE"
fi

if [[ -n "$NO_TIMELINE" ]]; then
    CMD="$CMD $NO_TIMELINE"
fi

if [[ -n "$LOG_FILE" ]]; then
    CMD="$CMD $LOG_FILE"
fi

if [[ -n "$NO_LOG" ]]; then
    CMD="$CMD $NO_LOG"
fi

# Display command being executed
print_header "🚀 Complete NAS Log Analysis Workflow"
echo ""
print_status "Input file: $INPUT_LOG"
if [[ -n "$OUTPUT_DIR" ]]; then
    print_status "Output directory: $OUTPUT_DIR"
fi
if [[ -n "$GROUP_BY" ]]; then
    print_status "Grouping criteria: $GROUP_BY"
fi
if [[ -n "$FORMATS" ]]; then
    print_status "Output formats: $FORMATS"
fi
if [[ -n "$VERBOSE" ]]; then
    print_status "Verbose logging: enabled"
fi
if [[ -n "$NO_SEQUENCE" ]]; then
    print_warning "Sequence diagrams: disabled"
fi
if [[ -n "$NO_TIMELINE" ]]; then
    print_warning "Timeline visualizations: disabled"
fi
echo ""

# Execute the command
print_status "Executing analysis workflow..."
echo "Command: $CMD"
echo ""

eval $CMD

# Check exit status
if [[ $? -eq 0 ]]; then
    print_status "✅ Analysis workflow completed successfully!"
    echo ""
    print_status "Check the output directory for results and visualizations."
else
    print_error "❌ Analysis workflow failed!"
    exit 1
fi 