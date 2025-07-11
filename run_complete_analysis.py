#!/usr/bin/env python3
"""
Complete NAS Log Analysis Workflow Script

This script drives the complete workflow for analyzing 3GPP NAS logs:
1. Parse raw log file into structured CSV
2. Group parsed data by various criteria
3. Perform advanced analysis with correlation and metrics
4. Generate visualizations and reports
5. Provide comprehensive output summary

Usage:
    python3 run_complete_analysis.py <log_file> [options]

Example:
    python3 run_complete_analysis.py data/raw_logs/NAS_speed_test_06-02.15-53-27-127.txt
"""

import argparse
import os
import sys
import subprocess
import time
from pathlib import Path
from datetime import datetime
import json
import pandas as pd

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.utils.logger import setup_logger
import structlog

logger = structlog.get_logger(__name__)


class CompleteAnalysisWorkflow:
    """Orchestrates the complete NAS log analysis workflow."""
    
    def __init__(self, verbose: bool = False, log_file: str = None):
        """Initialize the workflow with logging setup."""
        self.verbose = verbose
        self.log_file = log_file
        self.start_time = None
        self.results = {}
        self.run_log = []
        self.enable_logging = True
        
        # Setup logging
        log_level = "DEBUG" if verbose else "INFO"
        log_path = Path(log_file) if log_file else None
        
        setup_logger(
            name="complete_analysis",
            level=log_level,
            log_file=log_path,
            console_output=True
        )
        
        # Ensure output directories exist
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Ensure all required directories exist."""
        # Only create logs directory if needed
        Path("logs").mkdir(parents=True, exist_ok=True)
    
    def run_workflow(self, input_log: str, output_dir: str = None, 
                    group_by: list = None, analysis_formats: list = None,
                    generate_sequence: bool = True, generate_timeline: bool = True,
                    enable_logging: bool = True):
        """
        Run the complete analysis workflow.
        
        Args:
            input_log: Path to input log file
            output_dir: Output directory (default: output)
            group_by: List of grouping criteria (default: ['procedure', 'direction'])
            analysis_formats: List of analysis output formats (default: ['csv', 'json', 'html'])
            generate_sequence: Whether to generate sequence diagrams
            generate_timeline: Whether to generate timeline visualizations
        """
        self.start_time = time.time()
        
        # Set defaults
        if output_dir is None:
            output_dir = "output"
        
        if group_by is None:
            group_by = ['procedure', 'direction']
        
        if analysis_formats is None:
            analysis_formats = ['csv', 'json', 'html']
        
        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize run log
        self.run_log = []
        self.enable_logging = enable_logging
        if enable_logging:
            self._log_run_event("workflow_started", {
                "input_log": input_log,
                "output_dir": output_dir,
                "group_by": group_by,
                "analysis_formats": analysis_formats,
                "generate_sequence": generate_sequence,
                "generate_timeline": generate_timeline
            })
        
        logger.info("🚀 Starting Complete NAS Log Analysis Workflow", 
                   input_log=input_log, output_dir=output_dir)
        
        try:
            # Step 1: Parse the log file
            parsed_file = self._parse_log(input_log, output_dir)
            
            # Step 2: Group the parsed data
            grouped_files = self._group_data(parsed_file, output_dir, group_by)
            
            # Step 3: Perform advanced analysis
            analysis_files = self._analyze_data(parsed_file, output_dir, analysis_formats, 
                                              generate_sequence, generate_timeline, input_log)
            
            # Step 4: Generate summary report
            self._generate_summary_report(output_dir, parsed_file, grouped_files, analysis_files)
            
            # Step 5: Display results
            self._display_results(output_dir)
            
            # Step 6: Save run log
            if enable_logging:
                self._save_run_log(output_dir)
                
                self._log_run_event("workflow_completed", {
                    "duration_seconds": time.time() - self.start_time,
                    "success": True
                })
            
            logger.info("✅ Complete analysis workflow finished successfully")
            
        except Exception as e:
            if enable_logging:
                self._log_run_event("workflow_failed", {
                    "error": str(e),
                    "duration_seconds": time.time() - self.start_time,
                    "success": False
                })
                self._save_run_log(output_dir)
            logger.error("❌ Workflow failed", error=str(e))
            raise
    
    def _parse_log(self, input_log: str, output_dir: str) -> str:
        """Step 1: Parse the log file into structured CSV."""
        logger.info("🔍 Step 1: Parsing NAS log file")
        
        # Generate output filename
        input_path = Path(input_log)
        output_file = Path(output_dir) / f"{input_path.stem}_parsed.csv"
        
        if self.enable_logging:
            self._log_step_start("parsing", {
                "input_file": input_log,
                "output_file": str(output_file),
                "input_size_mb": self._get_file_size(input_log)
            })
        
        # Run parsing command
        cmd = [
            sys.executable, '-m', 'src.main', 'parse',
            '-i', str(input_log),
            '-o', str(output_file)
        ]
        
        result = self._run_command(cmd, "Parsing")
        
        if result['success']:
            stats = result.get('stats', {})
            if self.enable_logging:
                self._log_step_completed("parsing", {
                    "output_file": str(output_file),
                    "messages_extracted": stats.get('messages_extracted', 0),
                    "total_lines": stats.get('total_lines', 0),
                    "validation_errors": stats.get('validation_errors', 0),
                    "file_size_mb": stats.get('file_size_mb', 0),
                    "output_size_mb": self._get_file_size(str(output_file))
                })
            
            logger.info("✅ Parsing completed successfully", 
                       output_file=str(output_file),
                       messages_extracted=stats.get('messages_extracted', 0))
            return str(output_file)
        else:
            if self.enable_logging:
                self._log_step_failed("parsing", result['error'], {
                    "input_file": input_log,
                    "output_file": str(output_file)
                })
            raise RuntimeError(f"Parsing failed: {result['error']}")
    
    def _group_data(self, parsed_file: str, output_dir: str, group_by: list) -> list:
        """Step 2: Group the parsed data by specified criteria."""
        logger.info("📊 Step 2: Grouping parsed data", group_by=group_by)
        
        grouped_dir = Path(output_dir) / "grouped"
        grouped_dir.mkdir(exist_ok=True)
        
        if self.enable_logging:
            self._log_step_start("grouping", {
                "input_file": parsed_file,
                "output_dir": str(grouped_dir),
                "group_by": group_by,
                "input_size_mb": self._get_file_size(parsed_file),
                "input_rows": self._get_csv_row_count(parsed_file)
            })
        
        # Build grouping command
        cmd = [
            sys.executable, '-m', 'src.main', 'group',
            '-i', parsed_file,
            '-o', str(grouped_dir)
        ]
        
        # Add grouping criteria
        for criterion in group_by:
            cmd.extend(['-g', criterion])
        
        result = self._run_command(cmd, "Grouping")
        
        if result['success']:
            # Get list of grouped files
            grouped_files = list(grouped_dir.glob("*.csv"))
            grouped_file_info = []
            total_size = 0
            
            for f in grouped_files:
                file_size = self._get_file_size(str(f))
                row_count = self._get_csv_row_count(str(f))
                total_size += file_size
                grouped_file_info.append({
                    "file": str(f),
                    "size_mb": file_size,
                    "rows": row_count
                })
            
            if self.enable_logging:
                self._log_step_completed("grouping", {
                    "grouped_dir": str(grouped_dir),
                    "files_count": len(grouped_files),
                    "total_size_mb": total_size,
                    "grouped_files": grouped_file_info
                })
            
            logger.info("✅ Grouping completed successfully", 
                       files_count=len(grouped_files),
                       grouped_dir=str(grouped_dir))
            return [str(f) for f in grouped_files]
        else:
            if self.enable_logging:
                self._log_step_failed("grouping", result['error'], {
                    "input_file": parsed_file,
                    "output_dir": str(grouped_dir),
                    "group_by": group_by
                })
            raise RuntimeError(f"Grouping failed: {result['error']}")
    
    def _analyze_data(self, parsed_file: str, output_dir: str, formats: list,
                      generate_sequence: bool, generate_timeline: bool, input_log: str = None) -> dict:
        """Step 3: Perform advanced analysis on the parsed data."""
        logger.info("🧠 Step 3: Performing advanced analysis", formats=formats)
        
        analysis_dir = Path(output_dir) / "analysis"
        analysis_dir.mkdir(exist_ok=True)
        
        if self.enable_logging:
            self._log_step_start("analysis", {
                "input_file": parsed_file,
                "output_dir": str(analysis_dir),
                "formats": formats,
                "generate_sequence": generate_sequence,
                "generate_timeline": generate_timeline,
                "input_size_mb": self._get_file_size(parsed_file),
                "input_rows": self._get_csv_row_count(parsed_file)
            })
        
        # Build analysis command
        cmd = [
            sys.executable, '-m', 'src.main', 'analyze',
            '-i', parsed_file,
            '-o', str(analysis_dir)
        ]
        
        # Add output formats
        for format_type in formats:
            cmd.extend(['-f', format_type])
        
        # Add visualization options
        if generate_sequence:
            cmd.append('--sequence-diagram')
        
        if generate_timeline:
            cmd.append('--timeline')
        
        # Set environment variable for input file name
        env = os.environ.copy()
        if input_log:
            env['ORIGINAL_INPUT_FILE'] = input_log
        
        result = self._run_command(cmd, "Analysis", env)
        
        if result['success']:
            # Get list of analysis files
            analysis_files = list(analysis_dir.glob("*"))
            analysis_file_info = []
            total_size = 0
            
            for f in analysis_files:
                file_size = self._get_file_size(str(f))
                total_size += file_size
                analysis_file_info.append({
                    "file": str(f),
                    "size_mb": file_size,
                    "type": f.suffix[1:] if f.suffix else f.name
                })
            
            if self.enable_logging:
                self._log_step_completed("analysis", {
                    "analysis_dir": str(analysis_dir),
                    "files_count": len(analysis_files),
                    "total_size_mb": total_size,
                    "analysis_files": analysis_file_info
                })
            
            logger.info("✅ Analysis completed successfully", 
                       files_count=len(analysis_files),
                       analysis_dir=str(analysis_dir))
            return {f.suffix[1:] if f.suffix else f.name: str(f) for f in analysis_files}
        else:
            if self.enable_logging:
                self._log_step_failed("analysis", result['error'], {
                    "input_file": parsed_file,
                    "output_dir": str(analysis_dir),
                    "formats": formats,
                    "generate_sequence": generate_sequence,
                    "generate_timeline": generate_timeline
                })
            raise RuntimeError(f"Analysis failed: {result['error']}")
    
    def _generate_summary_report(self, output_dir: str, parsed_file: str, 
                                grouped_files: list, analysis_files: dict):
        """Step 4: Generate a comprehensive summary report."""
        logger.info("📋 Step 4: Generating summary report")
        
        if self.enable_logging:
            self._log_step_start("summary_report", {
                "output_dir": output_dir,
                "parsed_file": parsed_file,
                "grouped_files_count": len(grouped_files),
                "analysis_files_count": len(analysis_files)
            })
        
        report_file = Path(output_dir) / "analysis_summary.json"
        
        # Calculate file sizes and basic stats
        summary = {
            "workflow_info": {
                "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
                "duration_seconds": time.time() - self.start_time,
                "input_file": parsed_file,
                "output_directory": str(output_dir)
            },
            "files": {
                "parsed_file": {
                    "path": parsed_file,
                    "size_mb": self._get_file_size(parsed_file),
                    "message_count": self._get_csv_row_count(parsed_file)
                },
                "grouped_files": [
                    {
                        "path": f,
                        "size_mb": self._get_file_size(f),
                        "message_count": self._get_csv_row_count(f)
                    } for f in grouped_files
                ],
                "analysis_files": [
                    {
                        "path": f,
                        "size_mb": self._get_file_size(f),
                        "type": Path(f).suffix[1:] if Path(f).suffix else "unknown"
                    } for f in analysis_files.values()
                ]
            },
            "statistics": {
                "total_grouped_files": len(grouped_files),
                "total_analysis_files": len(analysis_files),
                "total_output_size_mb": sum(self._get_file_size(f) for f in [parsed_file] + grouped_files + list(analysis_files.values()))
            },
            "run_log_summary": {
                "total_events": len(self.run_log),
                "successful_steps": len([e for e in self.run_log if e["event_type"].endswith("_completed")]),
                "failed_steps": len([e for e in self.run_log if e["event_type"].endswith("_failed")]),
                "workflow_success": any(e["event_type"] == "workflow_completed" for e in self.run_log)
            }
        }
        
        # Save summary report
        with open(report_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        if self.enable_logging:
            self._log_step_completed("summary_report", {
                "report_file": str(report_file),
                "summary_size_mb": self._get_file_size(str(report_file))
            })
        
        logger.info("✅ Summary report generated", report_file=str(report_file))
        return summary
    
    def _display_results(self, output_dir: str):
        """Step 5: Display comprehensive results summary."""
        logger.info("📈 Step 5: Displaying results summary")
        
        if self.enable_logging:
            self._log_step_start("display_results", {"output_dir": output_dir})
        
        print("\n" + "="*80)
        print("🎉 COMPLETE NAS LOG ANALYSIS WORKFLOW - RESULTS SUMMARY")
        print("="*80)
        
        # Display timing
        duration = time.time() - self.start_time
        print(f"⏱️  Total processing time: {duration:.2f} seconds")
        
        # Display file structure
        print(f"\n📁 Output directory: {output_dir}")
        
        # List all generated files
        print("\n📋 Generated Files:")
        print("-" * 40)
        
        for file_path in Path(output_dir).rglob("*"):
            if file_path.is_file():
                size_mb = self._get_file_size(str(file_path))
                relative_path = file_path.relative_to(output_dir)
                print(f"  📄 {relative_path} ({size_mb:.2f} MB)")
        
        # Display key statistics
        parsed_file = next(Path(output_dir).glob("*_parsed.csv"), None)
        if parsed_file:
            message_count = self._get_csv_row_count(str(parsed_file))
            print(f"\n📊 Key Statistics:")
            print("-" * 20)
            print(f"  📝 Messages extracted: {message_count:,}")
            print(f"  📁 Grouped files: {len(list(Path(output_dir).glob('grouped/*.csv')))}")
            print(f"  📈 Analysis files: {len(list(Path(output_dir).glob('analysis/*')))}")
        
        # Display run log summary (only if logging is enabled)
        if self.enable_logging and self.run_log:
            print(f"\n📝 Run Log Summary:")
            print("-" * 20)
            successful_steps = len([e for e in self.run_log if e["event_type"].endswith("_completed")])
            failed_steps = len([e for e in self.run_log if e["event_type"].endswith("_failed")])
            total_events = len(self.run_log)
            
            print(f"  📊 Total events logged: {total_events}")
            print(f"  ✅ Successful steps: {successful_steps}")
            print(f"  ❌ Failed steps: {failed_steps}")
            print(f"  📄 Run log saved to: {output_dir}/run_log.json")
            
            # Show recent events
            recent_events = self.run_log[-5:] if len(self.run_log) > 5 else self.run_log
            if recent_events:
                print(f"\n🕒 Recent Events:")
                print("-" * 20)
                for event in recent_events:
                    timestamp = event["timestamp"].split("T")[1][:8]  # HH:MM:SS
                    event_type = event["event_type"]
                    print(f"  {timestamp} - {event_type}")
        
        print("\n" + "="*80)
        print("✅ Analysis workflow completed successfully!")
        print("💡 Check the output directory for detailed results and visualizations.")
        if self.enable_logging:
            print("📄 Run log available at: run_log.json")
        print("="*80 + "\n")
        
        if self.enable_logging:
            self._log_step_completed("display_results", {
                "total_events": total_events,
                "successful_steps": successful_steps,
                "failed_steps": failed_steps
            })
    
    def _run_command(self, cmd: list, step_name: str, env: dict = None) -> dict:
        """Run a subprocess command and return results."""
        logger.info(f"Running {step_name} command", command=' '.join(cmd))
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300,  # 5 minute timeout
                env=env
            )
            
            if result.returncode == 0:
                # Extract statistics from output
                stats = self._extract_stats_from_output(result.stdout)
                return {
                    'success': True,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'stats': stats
                }
            else:
                return {
                    'success': False,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'error': result.stderr or "Command failed with non-zero exit code"
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f"{step_name} timed out after 5 minutes"
            }
        except Exception as e:
            return {
                'success': False,
                'error': f"{step_name} failed: {str(e)}"
            }
    
    def _extract_stats_from_output(self, output: str) -> dict:
        """Extract statistics from command output."""
        stats = {}
        lines = output.split('\n')
        
        for line in lines:
            if 'Total lines processed:' in line:
                stats['total_lines'] = int(line.split(':')[1].strip().replace(',', ''))
            elif 'Messages extracted:' in line:
                stats['messages_extracted'] = int(line.split(':')[1].strip().replace(',', ''))
            elif 'Validation errors:' in line:
                stats['validation_errors'] = int(line.split(':')[1].strip())
            elif 'File size:' in line:
                stats['file_size_mb'] = float(line.split(':')[1].strip().replace(' MB', ''))
        
        return stats
    
    def _get_file_size(self, file_path: str) -> float:
        """Get file size in MB."""
        try:
            return Path(file_path).stat().st_size / (1024 * 1024)
        except:
            return 0.0
    
    def _get_csv_row_count(self, file_path: str) -> int:
        """Get number of rows in CSV file."""
        try:
            return len(pd.read_csv(file_path))
        except:
            return 0
    
    def _log_run_event(self, event_type: str, data: dict):
        """Log a run event with timestamp and data."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "data": data
        }
        self.run_log.append(event)
        logger.debug(f"Run event logged: {event_type}", **data)
    
    def _save_run_log(self, output_dir: str):
        """Save the run log to a JSON file."""
        try:
            log_file = Path(output_dir) / "run_log.json"
            with open(log_file, 'w') as f:
                json.dump(self.run_log, f, indent=2)
            logger.info(f"Run log saved to {log_file}")
        except Exception as e:
            logger.error(f"Failed to save run log: {e}")
    
    def _log_step_start(self, step_name: str, step_data: dict = None):
        """Log the start of a workflow step."""
        if step_data is None:
            step_data = {}
        self._log_run_event(f"{step_name}_started", step_data)
    
    def _log_step_completed(self, step_name: str, step_data: dict = None):
        """Log the completion of a workflow step."""
        if step_data is None:
            step_data = {}
        self._log_run_event(f"{step_name}_completed", step_data)
    
    def _log_step_failed(self, step_name: str, error: str, step_data: dict = None):
        """Log the failure of a workflow step."""
        if step_data is None:
            step_data = {}
        step_data["error"] = error
        self._log_run_event(f"{step_name}_failed", step_data)


def main():
    """Main entry point for the complete analysis workflow."""
    parser = argparse.ArgumentParser(
        description="Complete NAS Log Analysis Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run complete analysis with default settings
  python3 run_complete_analysis.py data/raw_logs/my_log.txt
  
  # Run with custom grouping and verbose output
  python3 run_complete_analysis.py data/raw_logs/my_log.txt \\
    --group-by procedure direction session \\
    --formats csv json html \\
    --verbose
  
  # Run with custom output directory
  python3 run_complete_analysis.py data/raw_logs/my_log.txt \\
    --output-dir results/my_analysis \\
    --no-sequence-diagram \\
    --no-timeline
        """
    )
    
    parser.add_argument('input_log', 
                       help='Path to input NAS log file')
    parser.add_argument('--output-dir', '-o',
                       help='Output directory (default: output)')
    parser.add_argument('--group-by', '-g', nargs='+',
                       choices=['procedure', 'message_type', 'session', 'direction'],
                       default=['procedure', 'direction'],
                       help='Grouping criteria (default: procedure direction)')
    parser.add_argument('--formats', '-f', nargs='+',
                       choices=['csv', 'json', 'excel', 'html', 'pdf'],
                       default=['csv', 'json', 'html'],
                       help='Analysis output formats (default: csv json html)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--log-file',
                       help='Log file path')
    parser.add_argument('--no-sequence-diagram', action='store_true',
                       help='Skip sequence diagram generation')
    parser.add_argument('--no-timeline', action='store_true',
                       help='Skip timeline visualization generation')
    parser.add_argument('--no-log', action='store_true',
                       help='Skip run log generation')
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.input_log):
        print(f"❌ Error: Input file '{args.input_log}' not found")
        sys.exit(1)
    
    # Create workflow instance
    workflow = CompleteAnalysisWorkflow(
        verbose=args.verbose,
        log_file=args.log_file
    )
    
    try:
        # Run the complete workflow
        workflow.run_workflow(
            input_log=args.input_log,
            output_dir=args.output_dir,
            group_by=args.group_by,
            analysis_formats=args.formats,
            generate_sequence=not args.no_sequence_diagram,
            generate_timeline=not args.no_timeline,
            enable_logging=not args.no_log
        )
        
        print("\n🎉 Analysis workflow completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Analysis workflow failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main() 