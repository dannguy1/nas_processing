#!/bin/bash

# run_analysis.sh - User-friendly wrapper for NAS log analysis
#
# Usage examples:
#   ./run_analysis.sh -i data/raw_logs/my_log.txt
#   ./run_analysis.sh -i data/raw_logs/my_log.txt -o results/enhanced
#   ./run_analysis.sh -i data/raw_logs/my_log.txt -m complete -g procedure direction
#   ./run_analysis.sh -i data/raw_logs/my_log.txt -f csv json html --verbose
#   ./run_analysis.sh --help

show_help() {
  echo "Usage: $0 -i <input_log> [options]"
  echo ""
  echo "Options:"
  echo "  -i, --input <file>         Input NAS log file (required)"
  echo "  -o, --output-dir <dir>     Output directory (default: auto/generated)"
  echo "  -m, --mode <mode>          Analysis mode: enhanced (default) or complete"
  echo "  -g, --group-by <fields>    Grouping criteria (for complete mode, e.g. procedure direction)"
  echo "  -f, --formats <formats>     Output formats (csv, json, html, etc.)"
  echo "  -v, --verbose              Enable verbose logging"
  echo "  --log-file <file>          Log file path"
  echo "  --no-sequence-diagram      Skip sequence diagram generation"
  echo "  --no-timeline              Skip timeline visualization generation"
  echo "  -h, --help                 Show this help message"
  echo ""
  echo "Examples:"
  echo "  $0 -i data/raw_logs/my_log.txt"
  echo "  $0 -i data/raw_logs/my_log.txt -o results/enhanced"
  echo "  $0 -i data/raw_logs/my_log.txt -m complete -g procedure direction"
  echo "  $0 -i data/raw_logs/my_log.txt -f csv json html --verbose"
}

# Default values
INPUT=""
OUTPUT_DIR=""
MODE=""
GROUP_BY=()
FORMATS=()
VERBOSE=""
LOG_FILE=""
NO_SEQ=""
NO_TIMELINE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--input)
      INPUT="$2"; shift 2;;
    -o|--output-dir)
      OUTPUT_DIR="$2"; shift 2;;
    -m|--mode)
      MODE="$2"; shift 2;;
    -g|--group-by)
      while [[ $# -gt 1 && ! "$2" =~ ^- ]]; do GROUP_BY+=("$2"); shift; done; shift;;
    -f|--formats)
      while [[ $# -gt 1 && ! "$2" =~ ^- ]]; do FORMATS+=("$2"); shift; done; shift;;
    -v|--verbose)
      VERBOSE="--verbose"; shift;;
    --log-file)
      LOG_FILE="--log-file $2"; shift 2;;
    --no-sequence-diagram)
      NO_SEQ="--no-sequence-diagram"; shift;;
    --no-timeline)
      NO_TIMELINE="--no-timeline"; shift;;
    -h|--help)
      show_help; exit 0;;
    *)
      echo "Unknown option: $1"; show_help; exit 1;;
  esac
done

if [[ -z "$INPUT" ]]; then
  echo "Error: Input log file is required."
  show_help
  exit 1
fi

CMD=(python3 run_analysis.py "$INPUT")

if [[ -n "$OUTPUT_DIR" ]]; then
  CMD+=(--output-dir "$OUTPUT_DIR")
fi
if [[ -n "$MODE" ]]; then
  CMD+=(--mode "$MODE")
fi
if [[ ${#GROUP_BY[@]} -gt 0 ]]; then
  CMD+=(--group-by "${GROUP_BY[@]}")
fi
if [[ ${#FORMATS[@]} -gt 0 ]]; then
  CMD+=(--formats "${FORMATS[@]}")
fi
if [[ -n "$VERBOSE" ]]; then
  CMD+=(--verbose)
fi
if [[ -n "$LOG_FILE" ]]; then
  CMD+=($LOG_FILE)
fi
if [[ -n "$NO_SEQ" ]]; then
  CMD+=(--no-sequence-diagram)
fi
if [[ -n "$NO_TIMELINE" ]]; then
  CMD+=(--no-timeline)
fi

# Print and run the command
echo "Running: ${CMD[@]}"
"${CMD[@]}" 