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
                                         visualization_files, basic_analysis_files, input_log)
        
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
        
        # Count messages with actual containers
        total_messages = len(df)
        messages_with_containers = len(df[df['has_embedded_containers'] == True])
        
        # Container types analysis based on actual data
        container_types = {
            'esm_container': len(df[df['bearer_id'].notna()]),
            'protocol_configs': len(df[df['qci'].notna()]),
            'qci': len(df[df['qci'].notna()]),
            'bearer_id': len(df[df['bearer_id'].notna()]),
            'bearer_state': len(df[df['bearer_state'].notna()]),
            'connection_id': len(df[df['connection_id'].notna()]),
            'vendor_specific': len(df[df['has_embedded_containers'] == True]),
            'container_contents': len(df[df['has_embedded_containers'] == True]),
            'protocol_lengths': len(df[df['has_embedded_containers'] == True]),
            'num_records': len(df[df['has_embedded_containers'] == True])
        }
        
        # Protocol distribution - analyze actual protocol data
        protocol_distribution = {}
        if 'protocol_container_types' in df.columns:
            for _, row in df.iterrows():
                if pd.notna(row.get('protocol_container_types')):
                    try:
                        # Handle string representation of list
                        if isinstance(row['protocol_container_types'], str):
                            protocols = eval(row['protocol_container_types'])
                        else:
                            protocols = row['protocol_container_types']
                        
                        for protocol in protocols:
                            protocol_distribution[protocol] = protocol_distribution.get(protocol, 0) + 1
                    except:
                        pass
        
        # If no protocol data found, use empty dict
        if not protocol_distribution:
            protocol_distribution = {}
        
        # Vendor container stats - analyze actual vendor data
        vendor_container_stats = {}
        if 'vendor_specific_count' in df.columns:
            for _, row in df.iterrows():
                if pd.notna(row.get('vendor_specific_count')) and row['vendor_specific_count'] > 0:
                    # For now, use a generic vendor ID since we don't have specific vendor data
                    vendor_container_stats['vendor_containers'] = vendor_container_stats.get('vendor_containers', 0) + row['vendor_specific_count']
        
        # QCI info - use actual QCI data
        qci_info = {}
        if 'qci' in df.columns:
            qci_values = df[df['qci'].notna()]['qci'].unique()
            if len(qci_values) > 0:
                qci_info['qci_value'] = qci_values[0]  # Use first QCI value found
        
        # Bearer ID info - use actual bearer ID data
        bearer_id_info = {}
        if 'bearer_id' in df.columns:
            bearer_values = df[df['bearer_id'].notna()]['bearer_id'].unique()
            if len(bearer_values) > 0:
                bearer_id_info['bearer_id_value'] = bearer_values[0]  # Use first bearer ID found
        
        # Bearer state info - use actual bearer state data
        bearer_state_info = {}
        if 'bearer_state' in df.columns:
            bearer_state_values = df[df['bearer_state'].notna()]['bearer_state'].unique()
            if len(bearer_state_values) > 0:
                bearer_state_info['bearer_state_value'] = bearer_state_values[0]  # Use first bearer state found
        
        # Connection ID info - use actual connection ID data
        connection_id_info = {}
        if 'connection_id' in df.columns:
            connection_values = df[df['connection_id'].notna()]['connection_id'].unique()
            if len(connection_values) > 0:
                connection_id_info['connection_id_value'] = connection_values[0]  # Use first connection ID found
        
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
                    'container_coverage_percentage': (messages_with_containers / total_messages) * 100 if total_messages > 0 else 0
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
                                    container_analysis: dict, visualization_files: dict, basic_analysis_files: dict = None, original_input_file: str = None):
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
                'input_file': original_input_file if original_input_file else parsed_file,
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
        
        # Generate top-level HTML dashboard
        self._generate_top_level_html_report(output_dir, report, 'enhanced')
        
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
        
        # Generate top-level HTML dashboard
        self._generate_top_level_html_report(output_dir, summary, 'complete')
        
        logger.info("✅ Summary report generated", report_file=str(report_file))
        return summary
    
    def _generate_top_level_html_report(self, output_dir: str, report: dict, mode: str):
        """Generate a top-level HTML report that serves as a dashboard/index page."""
        logger.info("🌐 Generating top-level HTML analysis report")
        
        output_path = Path(output_dir)
        
        # Collect all files in the output directory
        all_files = []
        for file_path in output_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in ['.html', '.csv', '.json', '.png', '.pdf']:
                relative_path = file_path.relative_to(output_path)
                size_mb = file_path.stat().st_size / (1024 * 1024)
                
                # Categorize files
                category = self._categorize_file(file_path)
                
                all_files.append({
                    'name': file_path.name,
                    'path': str(relative_path),
                    'size_mb': size_mb,
                    'category': category,
                    'type': file_path.suffix[1:].upper() if file_path.suffix else 'Unknown'
                })
        
        # Sort files by category and name
        all_files.sort(key=lambda x: (x['category'], x['name']))
        
        # Generate HTML content
        html_content = self._create_html_dashboard(report, all_files, mode)
        
        # Write HTML file
        html_file = output_path / "analysis_dashboard.html"
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info("✅ Top-level HTML report generated", html_file=str(html_file))
    
    def _categorize_file(self, file_path: Path) -> str:
        """Categorize a file based on its name and location."""
        name = file_path.name.lower()
        
        if 'dashboard' in name or 'index' in name:
            return 'Dashboard'
        elif 'parsed' in name:
            return 'Parsed Data'
        elif 'analysis' in name and 'report' in name:
            return 'Analysis Reports'
        elif 'sequence' in name:
            return 'Sequence Diagrams'
        elif 'timeline' in name:
            return 'Timeline Visualizations'
        elif 'container' in name:
            return 'Container Analysis'
        elif 'grouped' in name or file_path.parent.name == 'grouped':
            return 'Grouped Data'
        elif file_path.suffix == '.png':
            return 'Charts & Images'
        elif file_path.suffix == '.json':
            return 'Data Files'
        elif file_path.suffix == '.csv':
            return 'Data Files'
        elif file_path.suffix == '.html':
            return 'Interactive Reports'
        else:
            return 'Other Files'
    
    def _filter_files_for_category(self, category: str, files: list, mode: str) -> list:
        """Filter files for display based on category and mode."""
        if category == 'Analysis Reports':
            # Only show enhanced versions
            return [f for f in files if 'enhanced' in f['name'].lower()]
        
        elif category == 'Container Analysis':
            # Only show the 3 essential files
            essential_files = ['detailed_container_report.html', 'container_summary.png', 'container_analysis.json']
            return [f for f in files if f['name'] in essential_files]
        
        else:
            # Show all files for other categories
            return files
    
    def _create_html_dashboard(self, report: dict, files: list, mode: str) -> str:
        """Create HTML dashboard content."""
        workflow_info = report['workflow_info']
        files_info = report['files']
        
        # Calculate statistics
        total_files = len(files)
        total_size_mb = sum(f['size_mb'] for f in files)
        
        # Group files by category
        files_by_category = {}
        for file_info in files:
            category = file_info['category']
            if category not in files_by_category:
                files_by_category[category] = []
            files_by_category[category].append(file_info)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NAS Log Analysis Dashboard - {mode.title()} Mode</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            font-size: 1.2em;
            opacity: 0.9;
        }}
        .stats-bar {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{
            transform: translateY(-2px);
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }}
        .stat-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .section {{
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .category-header {{
            background: #f8f9fa;
            padding: 20px;
            font-size: 1.3em;
            font-weight: 600;
            color: #495057;
            border-bottom: 1px solid #e9ecef;
        }}
        .file-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            padding: 20px;
        }}
        .file-card {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            transition: all 0.2s;
        }}
        .file-card:hover {{
            background: #e9ecef;
            transform: translateX(5px);
        }}
        .file-name {{
            font-weight: 600;
            color: #495057;
            margin-bottom: 8px;
            font-size: 1.1em;
        }}
        .file-info {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            font-size: 0.9em;
        }}
        .file-size {{
            color: #6c757d;
        }}
        .file-type {{
            background: #667eea;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
        }}
        .file-link {{
            display: inline-block;
            background: #667eea;
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 5px;
            font-size: 0.9em;
            transition: background 0.2s;
        }}
        .file-link:hover {{
            background: #5a6fd8;
        }}
        .info-grid {{
            display: flex;
            flex-direction: column;
            gap: 15px;
        }}
        .info-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .info-label {{
            font-weight: bold;
            color: #6c757d;
            font-size: 0.9em;
        }}
        .info-value {{
            color: #495057;
            margin-top: 5px;
            word-break: break-all;
            overflow-wrap: break-word;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #e9ecef;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 NAS Log Analysis Dashboard</h1>
            <p>{mode.title()} Mode Analysis Results</p>
        </div>
        
        <div class="stats-bar">
            <div class="stat-card">
                <div class="stat-number">{total_files}</div>
                <div class="stat-label">Total Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_size_mb:.1f}</div>
                <div class="stat-label">Total Size (MB)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{workflow_info.get('duration_seconds', 0):.1f}s</div>
                <div class="stat-label">Processing Time</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{files_info.get('parsed_file', {}).get('message_count', 0)}</div>
                <div class="stat-label">Messages Analyzed</div>
            </div>
        </div>
        
        <div class="section">
            <div class="category-header">📊 Analysis Summary</div>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Input File</div>
                    <div class="info-value">{workflow_info.get('input_file', 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Output Directory</div>
                    <div class="info-value">{workflow_info.get('output_directory', 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Analysis Mode</div>
                    <div class="info-value">{mode.title()}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Generated At</div>
                    <div class="info-value">{workflow_info.get('start_time', 'N/A')}</div>
                </div>
            </div>
        </div>
"""
        
        # Add sections for each category with improved filtering
        for category, category_files in files_by_category.items():
            # Apply filtering based on category
            filtered_files = self._filter_files_for_category(category, category_files, mode)
            
            if filtered_files:  # Only show section if there are files to display
                html += f"""
            <div class="section">
                <div class="category-header">📁 {category}</div>
                <div class="file-grid">
"""
                
                for file_info in filtered_files:
                    html += f"""
                    <div class="file-card">
                        <div class="file-name">{file_info['name']}</div>
                        <div class="file-info">
                            <span class="file-size">{file_info['size_mb']:.2f} MB</span>
                            <span class="file-type">{file_info['type']}</span>
                        </div>
                        <a href="{file_info['path']}" class="file-link" target="_blank">Open File</a>
                    </div>
"""
                
                html += """
                </div>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p>Generated by NAS Log Processing System | Enhanced with container analysis and visualizations</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
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
            if container['bearer_id_info']:
                print(f"   • Primary Bearer ID: {container['bearer_id_info'].get('bearer_id_value', 'N/A')}")
            else:
                print(f"   • Primary Bearer ID: N/A")
            if container['qci_info']:
                print(f"   • QCI Value: {container['qci_info'].get('qci_value', 'N/A')}")
            else:
                print(f"   • QCI Value: N/A")
            
            # Visualization files
            print(f"\n📈 Generated Visualizations:")
            for viz_file in files['visualization_files']:
                print(f"   • {Path(viz_file['path']).name} ({viz_file['type'].upper()})")
            
            # Dashboard info
            dashboard_file = Path(output_dir) / "analysis_dashboard.html"
            if dashboard_file.exists():
                print(f"\n🌐 Analysis Dashboard:")
                print(f"   • Open {dashboard_file} in your browser for a complete overview")
                print(f"   • Navigate to all analysis files and visualizations")
                print(f"   • Interactive file browser with categorized results")
            
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
        
        # Dashboard info
        dashboard_file = Path(output_dir) / "analysis_dashboard.html"
        if dashboard_file.exists():
            print(f"\n🌐 Analysis Dashboard:")
            print(f"   • Open {dashboard_file} in your browser for a complete overview")
            print(f"   • Navigate to all analysis files and visualizations")
            print(f"   • Interactive file browser with categorized results")
        
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