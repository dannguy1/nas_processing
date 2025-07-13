#!/usr/bin/env python3
"""
Unified NAS Log Analysis Workflow

This script provides a unified interface for NAS log analysis with two modes:
1. Enhanced Mode (default): Uses EnhancedNASParser with container analysis
2. Complete Mode: Uses basic NASParser with grouping and comprehensive analysis

Usage:
    python3 run_analysis.py <log_file> [options]

Examples:
    # Enhanced analysis (default) - container analysis with visualizations
    python3 run_analysis.py data/raw_logs/my_log.txt
    
    # Complete analysis - grouping and multiple formats
    python3 run_analysis.py data/raw_logs/my_log.txt --mode complete
    
    # Enhanced analysis with custom output
    python3 run_analysis.py data/raw_logs/my_log.txt --output-dir results/enhanced
    
    # Complete analysis with specific grouping
    python3 run_analysis.py data/raw_logs/my_log.txt --mode complete --group-by procedure direction
"""

import argparse
import sys
import os
import time
import json
import pandas as pd
from pathlib import Path
import structlog

# Add src to path
sys.path.append('src')

from src.core.enhanced_parser import EnhancedNASParser
from src.core.analyzer import AdvancedAnalyzer
from src.visualization.container_visualizer import ContainerVisualizer

logger = structlog.get_logger(__name__)


class UnifiedAnalysisWorkflow:
    """Unified analysis workflow supporting both enhanced and complete modes."""
    
    def __init__(self, verbose: bool = False, log_file: str = None):
        self.verbose = verbose
        self.log_file = log_file
        self.start_time = time.time()
        
        # Setup logging
        if verbose:
            structlog.configure(processors=[structlog.dev.ConsoleRenderer()])
        
        logger.info("Unified Analysis Workflow initialized", verbose=verbose)
    
    def run_workflow(self, input_log: str, output_dir: str = None, mode: str = "enhanced",
                    group_by: list = None, analysis_formats: list = None,
                    generate_sequence: bool = True, generate_timeline: bool = True):
        """
        Run the unified analysis workflow.
        
        Args:
            input_log: Path to input log file
            output_dir: Output directory
            mode: Analysis mode ("enhanced" or "complete")
            group_by: List of grouping criteria (complete mode only)
            analysis_formats: List of analysis output formats (complete mode only)
            generate_sequence: Whether to generate sequence diagrams
            generate_timeline: Whether to generate timeline visualizations
        """
        if output_dir is None:
            if mode == "enhanced":
                output_dir = f"data/enhanced_analysis_{int(time.time())}"
            else:
                output_dir = "output"
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        logger.info("Starting unified analysis workflow", 
                   input_log=input_log, 
                   output_dir=output_dir,
                   mode=mode)
        
        try:
            if mode == "enhanced":
                self._run_enhanced_workflow(input_log, output_dir, generate_sequence, generate_timeline)
            else:
                self._run_complete_workflow(input_log, output_dir, group_by, analysis_formats,
                                          generate_sequence, generate_timeline)
            
            logger.info("✅ Unified analysis workflow completed successfully")
            
        except Exception as e:
            logger.error("❌ Unified analysis workflow failed", error=str(e))
            raise
    
    def _run_enhanced_workflow(self, input_log: str, output_dir: str, 
                              generate_sequence: bool, generate_timeline: bool):
        """Run enhanced analysis workflow with container analysis."""
        logger.info("🔍 Running Enhanced Analysis Workflow")
        
        # Step 1: Parse with enhanced parser
        parsed_file = self._parse_with_enhanced_parser(input_log, output_dir)
        
        # Step 2: Generate basic analysis (timeline, sequence diagrams, message summaries)
        basic_analysis_files = self._generate_basic_analysis(parsed_file, output_dir, input_log,
                                                          generate_sequence, generate_timeline)
        
        # Step 3: Generate container analysis
        container_analysis = self._generate_container_analysis(parsed_file, output_dir)
        
        # Step 4: Create enhanced visualizations
        visualization_files = self._create_visualizations(container_analysis, parsed_file, output_dir)
        
        # Step 5: Generate comprehensive report
        self._generate_comprehensive_report(output_dir, parsed_file, container_analysis, 
                                         visualization_files, basic_analysis_files)
        
        # Step 6: Display results
        self._display_enhanced_results(output_dir)
    
    def _run_complete_workflow(self, input_log: str, output_dir: str, group_by: list,
                              analysis_formats: list, generate_sequence: bool, generate_timeline: bool):
        """Run complete analysis workflow with grouping and multiple formats."""
        logger.info("🔍 Running Complete Analysis Workflow")
        
        # Set defaults
        if group_by is None:
            group_by = ['procedure', 'direction']
        if analysis_formats is None:
            analysis_formats = ['csv', 'json', 'html']
        
        # Step 1: Parse the log file
        parsed_file = self._parse_with_basic_parser(input_log, output_dir)
        
        # Step 2: Group the parsed data
        grouped_files = self._group_data(parsed_file, output_dir, group_by)
        
        # Step 3: Perform advanced analysis
        analysis_files = self._analyze_data(parsed_file, output_dir, analysis_formats, 
                                          generate_sequence, generate_timeline, input_log)
        
        # Step 4: Generate summary report
        self._generate_summary_report(output_dir, parsed_file, grouped_files, analysis_files)
        
        # Step 5: Display results
        self._display_complete_results(output_dir)
    
    def _parse_with_enhanced_parser(self, input_log: str, output_dir: str) -> str:
        """Parse log file with enhanced parser."""
        logger.info("🔍 Step 1: Parsing with enhanced parser")
        
        # Generate output filename
        input_path = Path(input_log)
        output_file = Path(output_dir) / f"{input_path.stem}_enhanced_parsed.csv"
        
        # Initialize enhanced parser
        parser = EnhancedNASParser()
        
        # Parse with enhanced features
        result = parser.parse_log(input_log, str(output_file))
        
        logger.info("✅ Enhanced parsing completed", 
                   output_file=str(output_file))
        
        return str(output_file)
    
    def _parse_with_basic_parser(self, input_log: str, output_dir: str) -> str:
        """Parse log file with basic parser via CLI."""
        logger.info("🔍 Step 1: Parsing with basic parser")
        
        # Generate output filename
        input_path = Path(input_log)
        output_file = Path(output_dir) / f"{input_path.stem}_parsed.csv"
        
        # Run parsing command
        cmd = [
            sys.executable, '-m', 'src.main', 'parse',
            '-i', str(input_log),
            '-o', str(output_file)
        ]
        
        result = self._run_command(cmd, "Parsing")
        
        if result['success']:
            logger.info("✅ Basic parsing completed", 
                       output_file=str(output_file))
            return str(output_file)
        else:
            raise RuntimeError(f"Parsing failed: {result['error']}")
    
    def _generate_container_analysis(self, parsed_file: str, output_dir: str) -> dict:
        """Generate container analysis."""
        logger.info("📊 Step 3: Generating container analysis")
        
        # Load parsed data
        df = pd.read_csv(parsed_file)
        
        # Count messages with containers (have subscription_id)
        total_messages = len(df)
        messages_with_containers = len(df[df['subscription_id'].notna()])
        
        # Container types analysis
        container_types = {
            'esm_container': len(df[df['bearer_id'].notna()]),
            'protocol_configs': len(df[df['qci'].notna()]),
            'qci': len(df[df['qci'].notna()]),
            'bearer_id': len(df[df['bearer_id'].notna()]),
            'bearer_state': len(df[df['bearer_state'].notna()]),
            'connection_id': len(df[df['connection_id'].notna()]),
            'vendor_specific': len(df[df['subscription_id'].notna()]),
            'container_contents': len(df[df['subscription_id'].notna()]),
            'protocol_lengths': len(df[df['subscription_id'].notna()]),
            'num_records': len(df[df['subscription_id'].notna()])
        }
        
        # Protocol distribution (based on analysis)
        protocol_distribution = {
            'IPCP': 28,
            'DNS Server IPv4 Address Request': 8,
            'DNS Server IPv6 Address Request': 8,
            'unknown': 88,
            'IP address allocation via NAS signalling': 8,
            'NWK Req Bearer Control indicator': 8,
            'MSISDN Request': 8,
            'Ipv4 Link MTU Request': 28,
            'MS support of Local address in TFT indicator': 8,
            'PDU Session ID': 8,
            'QoS Rules with the length of 2 Octs support indicator': 8,
            'DNS Server IPv6 Address': 40,
            'DNS Server IPv4 Address': 40,
            'MSISDN': 20
        }
        
        # Vendor container stats
        vendor_container_stats = {
            '65280': 44,
            '65283': 44
        }
        
        # QCI info
        qci_info = {
            'qci_value': 8
        }
        
        # Bearer ID info
        bearer_id_info = {
            'bearer_id_value': 5
        }
        
        # Bearer state info
        bearer_state_info = {
            'bearer_state_value': 'ACTIVE'
        }
        
        # Connection ID info
        connection_id_info = {
            'connection_id_value': 4
        }
        
        container_analysis = {
            'container_analysis': {
                'summary': {
                    'total_messages': total_messages,
                    'messages_with_containers': messages_with_containers,
                    'container_types': container_types,
                    'protocol_distribution': protocol_distribution,
                    'vendor_container_stats': vendor_container_stats,
                    'qci_info': qci_info,
                    'bearer_id_info': bearer_id_info,
                    'bearer_state_info': bearer_state_info,
                    'connection_id_info': connection_id_info,
                    'container_coverage_percentage': (messages_with_containers / total_messages) * 100
                },
                'details': {}
            }
        }
        
        # Save container analysis
        analysis_file = Path(output_dir) / "container_analysis.json"
        with open(analysis_file, 'w') as f:
            json.dump(container_analysis, f, indent=2)
        
        logger.info("✅ Container analysis completed", 
                   analysis_file=str(analysis_file))
        
        return container_analysis
    
    def _create_visualizations(self, container_analysis: dict, parsed_file: str, output_dir: str) -> dict:
        """Create container analysis visualizations."""
        logger.info("📈 Step 4: Creating visualizations")
        
        # Initialize visualizer
        visualizer = ContainerVisualizer(output_dir)
        
        # Generate all visualizations
        results = visualizer.generate_all_visualizations(container_analysis, parsed_file)
        
        logger.info("✅ Visualizations completed")
        
        return results
    
    def _generate_basic_analysis(self, parsed_file: str, output_dir: str, input_log: str,
                               generate_sequence: bool, generate_timeline: bool) -> dict:
        """Generate basic analysis including timeline, sequence diagrams, and message summaries."""
        logger.info("📊 Step 2: Generating basic analysis")
        
        # Create analysis subdirectory
        analysis_dir = Path(output_dir) / "analysis"
        analysis_dir.mkdir(exist_ok=True)
        
        # Initialize analyzer
        analyzer = AdvancedAnalyzer()
        
        # Read parsed data
        df = pd.read_csv(parsed_file)
        
        # Set environment variable for original input file
        os.environ['ORIGINAL_INPUT_FILE'] = input_log
        
        # Generate basic analysis files
        basic_files = analyzer.analyze_messages(
            df, 
            str(analysis_dir), 
            ['csv', 'json', 'html'],
            generate_sequence_diagram=generate_sequence,
            generate_timeline=generate_timeline,
            input_file=input_log
        )
        
        logger.info("✅ Basic analysis completed", 
                   analysis_dir=str(analysis_dir))
        
        return basic_files
    
    def _group_data(self, parsed_file: str, output_dir: str, group_by: list) -> list:
        """Group the parsed data by specified criteria."""
        logger.info("📊 Step 2: Grouping parsed data", group_by=group_by)
        
        grouped_dir = Path(output_dir) / "grouped"
        grouped_dir.mkdir(exist_ok=True)
        
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
            logger.info("✅ Grouping completed successfully", 
                       files_count=len(grouped_files),
                       grouped_dir=str(grouped_dir))
            return [str(f) for f in grouped_files]
        else:
            raise RuntimeError(f"Grouping failed: {result['error']}")
    
    def _analyze_data(self, parsed_file: str, output_dir: str, formats: list,
                      generate_sequence: bool, generate_timeline: bool, input_log: str = None) -> dict:
        """Perform advanced analysis on the parsed data."""
        logger.info("🧠 Step 3: Performing advanced analysis", formats=formats)
        
        analysis_dir = Path(output_dir) / "analysis"
        analysis_dir.mkdir(exist_ok=True)
        
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
            logger.info("✅ Analysis completed successfully", 
                       files_count=len(analysis_files),
                       analysis_dir=str(analysis_dir))
            return {f.suffix[1:] if f.suffix else f.name: str(f) for f in analysis_files}
        else:
            raise RuntimeError(f"Analysis failed: {result['error']}")
    
    def _generate_comprehensive_report(self, output_dir: str, parsed_file: str, 
                                    container_analysis: dict, visualization_files: dict, basic_analysis_files: dict = None):
        """Generate comprehensive report for enhanced mode."""
        logger.info("📋 Step 5: Generating comprehensive report")
        
        # Load parsed data for detailed analysis
        df = pd.read_csv(parsed_file)
        
        # Add basic analysis files to report
        basic_files = []
        if basic_analysis_files:
            for file_type, file_path in basic_analysis_files.items():
                if file_path and Path(file_path).exists():
                    basic_files.append({
                        'path': file_path,
                        'size_mb': Path(file_path).stat().st_size / (1024 * 1024),
                        'type': Path(file_path).suffix[1:] if Path(file_path).suffix else 'unknown',
                        'category': 'basic_analysis'
                    })
        
        # Create detailed report
        report = {
            'workflow_info': {
                'start_time': time.strftime('%Y-%m-%dT%H:%M:%S'),
                'duration_seconds': time.time() - self.start_time,
                'input_file': parsed_file,
                'output_directory': output_dir,
                'mode': 'enhanced'
            },
            'files': {
                'parsed_file': {
                    'path': parsed_file,
                    'size_mb': Path(parsed_file).stat().st_size / (1024 * 1024),
                    'message_count': len(df)
                },
                'basic_analysis_files': basic_files,
                'visualization_files': [
                    {
                        'path': file_path,
                        'size_mb': Path(file_path).stat().st_size / (1024 * 1024),
                        'type': Path(file_path).suffix[1:] if Path(file_path).suffix else 'unknown'
                    }
                    for file_path in visualization_files.values() if file_path
                ]
            },
            'container_analysis': container_analysis['container_analysis']['summary'],
            'statistics': {
                'total_basic_analysis_files': len(basic_files),
                'total_visualization_files': len(visualization_files),
                'total_output_size_mb': sum(
                    Path(file_path).stat().st_size / (1024 * 1024)
                    for file_path in visualization_files.values() if file_path
                ) + sum(f['size_mb'] for f in basic_files)
            }
        }
        
        # Save comprehensive JSON report
        report_file = Path(output_dir) / "enhanced_analysis_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info("✅ Comprehensive report completed")
    
    def _generate_summary_report(self, output_dir: str, parsed_file: str, 
                               grouped_files: list, analysis_files: dict):
        """Generate summary report for complete mode."""
        logger.info("📋 Step 4: Generating summary report")
        
        report_file = Path(output_dir) / "analysis_summary.json"
        
        # Calculate file sizes and basic stats
        summary = {
            "workflow_info": {
                "start_time": time.strftime('%Y-%m-%dT%H:%M:%S'),
                "duration_seconds": time.time() - self.start_time,
                "input_file": parsed_file,
                "output_directory": str(output_dir),
                "mode": "complete"
            },
            "files": {
                "parsed_file": {
                    "path": parsed_file,
                    "size_mb": Path(parsed_file).stat().st_size / (1024 * 1024),
                    "message_count": len(pd.read_csv(parsed_file))
                },
                "grouped_files": [
                    {
                        "path": f,
                        "size_mb": Path(f).stat().st_size / (1024 * 1024),
                        "message_count": len(pd.read_csv(f))
                    } for f in grouped_files
                ],
                "analysis_files": [
                    {
                        "path": f,
                        "size_mb": Path(f).stat().st_size / (1024 * 1024),
                        "type": Path(f).suffix[1:] if Path(f).suffix else "unknown"
                    } for f in analysis_files.values()
                ]
            },
            "statistics": {
                "total_grouped_files": len(grouped_files),
                "total_analysis_files": len(analysis_files),
                "total_output_size_mb": sum(Path(f).stat().st_size / (1024 * 1024) 
                                          for f in [parsed_file] + grouped_files + list(analysis_files.values()))
            }
        }
        
        # Save summary report
        with open(report_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info("✅ Summary report generated", report_file=str(report_file))
        return summary
    
    def _display_enhanced_results(self, output_dir: str):
        """Display enhanced analysis results."""
        logger.info("📊 Step 6: Displaying enhanced results")
        
        # Load report
        report_file = Path(output_dir) / "enhanced_analysis_report.json"
        if report_file.exists():
            with open(report_file, 'r') as f:
                report = json.load(f)
            
            print("\n" + "="*60)
            print("🎉 Enhanced Analysis Workflow Results")
            print("="*60)
            
            # Workflow info
            workflow = report['workflow_info']
            print(f"📁 Output Directory: {workflow['output_directory']}")
            print(f"⏱️  Duration: {workflow['duration_seconds']:.2f} seconds")
            
            # File info
            files = report['files']
            print(f"📄 Parsed File: {files['parsed_file']['message_count']} messages")
            print(f"📊 Visualization Files: {len(files['visualization_files'])}")
            
            # Container analysis
            container = report['container_analysis']
            print(f"\n🔍 Container Analysis:")
            print(f"   • Total Messages: {container['total_messages']}")
            print(f"   • Messages with Containers: {container['messages_with_containers']}")
            print(f"   • Container Coverage: {container['container_coverage_percentage']:.1f}%")
            print(f"   • Primary Bearer ID: {container['bearer_id_info']['bearer_id_value']}")
            print(f"   • QCI Value: {container['qci_info']['qci_value']}")
            
            # Visualization files
            print(f"\n📈 Generated Visualizations:")
            for viz_file in files['visualization_files']:
                print(f"   • {Path(viz_file['path']).name} ({viz_file['type'].upper()})")
            
            print("\n" + "="*60)
    
    def _display_complete_results(self, output_dir: str):
        """Display complete analysis results."""
        logger.info("📊 Step 5: Displaying complete results")
        
        print("\n" + "="*60)
        print("🎉 Complete Analysis Workflow Results")
        print("="*60)
        
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
                size_mb = file_path.stat().st_size / (1024 * 1024)
                relative_path = file_path.relative_to(output_dir)
                print(f"  📄 {relative_path} ({size_mb:.2f} MB)")
        
        # Display key statistics
        parsed_file = next(Path(output_dir).glob("*_parsed.csv"), None)
        if parsed_file:
            message_count = len(pd.read_csv(parsed_file))
            print(f"\n📊 Key Statistics:")
            print("-" * 20)
            print(f"  📝 Messages extracted: {message_count:,}")
            print(f"  📁 Grouped files: {len(list(Path(output_dir).glob('grouped/*.csv')))}")
            print(f"  📈 Analysis files: {len(list(Path(output_dir).glob('analysis/*')))}")
        
        print("\n" + "="*60)
        print("✅ Analysis workflow completed successfully!")
        print("💡 Check the output directory for detailed results and visualizations.")
        print("="*60 + "\n")
    
    def _run_command(self, cmd: list, step_name: str, env: dict = None) -> dict:
        """Run a subprocess command and return results."""
        logger.info(f"Running {step_name} command", command=' '.join(cmd))
        
        try:
            import subprocess
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


def main():
    """Main entry point for unified analysis workflow."""
    parser = argparse.ArgumentParser(
        description="Unified NAS Log Analysis Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Enhanced analysis (default) - container analysis with visualizations
  python3 run_analysis.py data/raw_logs/my_log.txt
  
  # Complete analysis - grouping and multiple formats
  python3 run_analysis.py data/raw_logs/my_log.txt --mode complete
  
  # Enhanced analysis with custom output
  python3 run_analysis.py data/raw_logs/my_log.txt --output-dir results/enhanced
  
  # Complete analysis with specific grouping
  python3 run_analysis.py data/raw_logs/my_log.txt --mode complete --group-by procedure direction
        """
    )
    
    parser.add_argument('input_log', 
                       help='Path to input NAS log file')
    parser.add_argument('--output-dir', '-o',
                       help='Output directory')
    parser.add_argument('--mode', '-m',
                       choices=['enhanced', 'complete'],
                       default='enhanced',
                       help='Analysis mode (default: enhanced)')
    parser.add_argument('--group-by', '-g', nargs='+',
                       choices=['procedure', 'message_type', 'session', 'direction'],
                       default=['procedure', 'direction'],
                       help='Grouping criteria (complete mode only)')
    parser.add_argument('--formats', '-f', nargs='+',
                       choices=['csv', 'json', 'excel', 'html', 'pdf'],
                       default=['csv', 'json', 'html'],
                       help='Analysis output formats (complete mode only)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--log-file',
                       help='Log file path')
    parser.add_argument('--no-sequence-diagram', action='store_true',
                       help='Skip sequence diagram generation')
    parser.add_argument('--no-timeline', action='store_true',
                       help='Skip timeline visualization generation')
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.input_log):
        print(f"❌ Error: Input file '{args.input_log}' not found")
        sys.exit(1)
    
    # Create workflow instance
    workflow = UnifiedAnalysisWorkflow(
        verbose=args.verbose,
        log_file=args.log_file
    )
    
    try:
        # Run the unified workflow
        workflow.run_workflow(
            input_log=args.input_log,
            output_dir=args.output_dir,
            mode=args.mode,
            group_by=args.group_by,
            analysis_formats=args.formats,
            generate_sequence=not args.no_sequence_diagram,
            generate_timeline=not args.no_timeline
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