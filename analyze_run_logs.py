#!/usr/bin/env python3
"""
Run Log Analysis Utility

This script analyzes run logs from multiple workflow executions to provide
insights into performance, success rates, and common issues.

Usage:
    python3 analyze_run_logs.py [run_log_directory]
    
Example:
    python3 analyze_run_logs.py data/analysis_results/
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import pandas as pd

def load_run_logs(log_directory: str) -> list:
    """Load all run logs from the specified directory."""
    log_dir = Path(log_directory)
    run_logs = []
    
    if not log_dir.exists():
        print(f"❌ Directory not found: {log_directory}")
        return []
    
    # Find all run_log.json files
    for run_log_file in log_dir.rglob("run_log.json"):
        try:
            with open(run_log_file, 'r') as f:
                run_log = json.load(f)
                # Add metadata about the run
                run_log['_metadata'] = {
                    'log_file': str(run_log_file),
                    'run_directory': str(run_log_file.parent),
                    'run_name': run_log_file.parent.name
                }
                run_logs.append(run_log)
        except Exception as e:
            print(f"⚠️  Error loading {run_log_file}: {e}")
    
    return run_logs

def analyze_run_logs(run_logs: list) -> dict:
    """Analyze run logs and generate statistics."""
    if not run_logs:
        return {}
    
    analysis = {
        'summary': {
            'total_runs': len(run_logs),
            'successful_runs': 0,
            'failed_runs': 0,
            'total_events': 0,
            'date_range': {'start': None, 'end': None}
        },
        'performance': {
            'durations': [],
            'file_sizes': [],
            'message_counts': []
        },
        'events': {
            'event_types': Counter(),
            'step_success_rates': defaultdict(lambda: {'success': 0, 'total': 0}),
            'errors': []
        },
        'runs': []
    }
    
    for run_log in run_logs:
        run_analysis = analyze_single_run(run_log)
        analysis['runs'].append(run_analysis)
        
        # Update summary statistics
        analysis['summary']['total_events'] += len(run_log)
        
        # Track success/failure
        workflow_completed = any(e['event_type'] == 'workflow_completed' for e in run_log)
        if workflow_completed:
            analysis['summary']['successful_runs'] += 1
        else:
            analysis['summary']['failed_runs'] += 1
        
        # Track date range
        timestamps = [e['timestamp'] for e in run_log if 'timestamp' in e]
        if timestamps:
            run_start = min(timestamps)
            run_end = max(timestamps)
            
            if analysis['summary']['date_range']['start'] is None:
                analysis['summary']['date_range']['start'] = run_start
            else:
                analysis['summary']['date_range']['start'] = min(
                    analysis['summary']['date_range']['start'], run_start
                )
            
            if analysis['summary']['date_range']['end'] is None:
                analysis['summary']['date_range']['end'] = run_end
            else:
                analysis['summary']['date_range']['end'] = max(
                    analysis['summary']['date_range']['end'], run_end
                )
        
        # Track performance metrics
        if 'duration_seconds' in run_analysis:
            analysis['performance']['durations'].append(run_analysis['duration_seconds'])
        
        if 'input_size_mb' in run_analysis:
            analysis['performance']['file_sizes'].append(run_analysis['input_size_mb'])
        
        if 'messages_extracted' in run_analysis:
            analysis['performance']['message_counts'].append(run_analysis['messages_extracted'])
        
        # Track event types and step success rates
        for event in run_log:
            event_type = event['event_type']
            analysis['events']['event_types'][event_type] += 1
            
            # Track step success rates
            if event_type.endswith('_started'):
                step_name = event_type.replace('_started', '')
                analysis['events']['step_success_rates'][step_name]['total'] += 1
            elif event_type.endswith('_completed'):
                step_name = event_type.replace('_completed', '')
                analysis['events']['step_success_rates'][step_name]['success'] += 1
            elif event_type.endswith('_failed'):
                step_name = event_type.replace('_failed', '')
                analysis['events']['step_success_rates'][step_name]['total'] += 1
                # Record error
                if 'data' in event and 'error' in event['data']:
                    analysis['events']['errors'].append({
                        'step': step_name,
                        'error': event['data']['error'],
                        'timestamp': event['timestamp'],
                        'run': run_analysis.get('run_name', 'unknown')
                    })
    
    # Calculate success rates
    for step, counts in analysis['events']['step_success_rates'].items():
        if counts['total'] > 0:
            counts['success_rate'] = counts['success'] / counts['total']
        else:
            counts['success_rate'] = 0.0
    
    return analysis

def analyze_single_run(run_log: list) -> dict:
    """Analyze a single run log."""
    analysis = {
        'run_name': run_log[0].get('_metadata', {}).get('run_name', 'unknown'),
        'total_events': len(run_log),
        'successful_steps': 0,
        'failed_steps': 0,
        'workflow_success': False
    }
    
    # Extract workflow info
    workflow_started = None
    workflow_completed = None
    
    for event in run_log:
        if event['event_type'] == 'workflow_started':
            workflow_started = event['timestamp']
            if 'data' in event:
                analysis.update({
                    'input_file': event['data'].get('input_log', 'unknown'),
                    'output_dir': event['data'].get('output_dir', 'unknown'),
                    'group_by': event['data'].get('group_by', []),
                    'analysis_formats': event['data'].get('analysis_formats', [])
                })
        elif event['event_type'] == 'workflow_completed':
            workflow_completed = event['timestamp']
            analysis['workflow_success'] = True
            if 'data' in event:
                analysis['duration_seconds'] = event['data'].get('duration_seconds', 0)
        elif event['event_type'] == 'workflow_failed':
            workflow_completed = event['timestamp']
            analysis['workflow_success'] = False
            if 'data' in event:
                analysis['duration_seconds'] = event['data'].get('duration_seconds', 0)
                analysis['error'] = event['data'].get('error', 'unknown error')
        
        # Count step outcomes
        if event['event_type'].endswith('_completed'):
            analysis['successful_steps'] += 1
        elif event['event_type'].endswith('_failed'):
            analysis['failed_steps'] += 1
    
    # Extract performance metrics from parsing step
    for event in run_log:
        if event['event_type'] == 'parsing_completed' and 'data' in event:
            data = event['data']
            analysis.update({
                'messages_extracted': data.get('messages_extracted', 0),
                'total_lines': data.get('total_lines', 0),
                'validation_errors': data.get('validation_errors', 0),
                'input_size_mb': data.get('file_size_mb', 0),
                'output_size_mb': data.get('output_size_mb', 0)
            })
            break
    
    return analysis

def print_analysis_report(analysis: dict):
    """Print a comprehensive analysis report."""
    if not analysis:
        print("❌ No run logs found to analyze")
        return
    
    print("\n" + "="*80)
    print("📊 RUN LOG ANALYSIS REPORT")
    print("="*80)
    
    # Summary statistics
    summary = analysis['summary']
    print(f"\n📈 Summary Statistics:")
    print("-" * 30)
    print(f"  📊 Total runs analyzed: {summary['total_runs']}")
    print(f"  ✅ Successful runs: {summary['successful_runs']}")
    print(f"  ❌ Failed runs: {summary['failed_runs']}")
    print(f"  📝 Total events logged: {summary['total_events']}")
    
    if summary['successful_runs'] > 0:
        success_rate = summary['successful_runs'] / summary['total_runs'] * 100
        print(f"  🎯 Success rate: {success_rate:.1f}%")
    
    # Date range
    if summary['date_range']['start'] and summary['date_range']['end']:
        start_date = summary['date_range']['start'][:10]
        end_date = summary['date_range']['end'][:10]
        print(f"  📅 Date range: {start_date} to {end_date}")
    
    # Performance metrics
    if analysis['performance']['durations']:
        durations = analysis['performance']['durations']
        print(f"\n⏱️  Performance Metrics:")
        print("-" * 30)
        print(f"  🕒 Average duration: {sum(durations)/len(durations):.2f} seconds")
        print(f"  🕒 Min duration: {min(durations):.2f} seconds")
        print(f"  🕒 Max duration: {max(durations):.2f} seconds")
    
    if analysis['performance']['file_sizes']:
        file_sizes = analysis['performance']['file_sizes']
        print(f"  📁 Average input size: {sum(file_sizes)/len(file_sizes):.2f} MB")
        print(f"  📁 Min input size: {min(file_sizes):.2f} MB")
        print(f"  📁 Max input size: {max(file_sizes):.2f} MB")
    
    if analysis['performance']['message_counts']:
        message_counts = analysis['performance']['message_counts']
        print(f"  📝 Average messages extracted: {sum(message_counts)/len(message_counts):.0f}")
        print(f"  📝 Min messages: {min(message_counts)}")
        print(f"  📝 Max messages: {max(message_counts)}")
    
    # Step success rates
    print(f"\n🔧 Step Success Rates:")
    print("-" * 30)
    for step, stats in analysis['events']['step_success_rates'].items():
        if stats['total'] > 0:
            success_rate = stats['success_rate'] * 100
            print(f"  {step:20} {success_rate:5.1f}% ({stats['success']}/{stats['total']})")
    
    # Most common events
    print(f"\n📊 Most Common Events:")
    print("-" * 30)
    for event_type, count in analysis['events']['event_types'].most_common(10):
        print(f"  {event_type:30} {count:3d}")
    
    # Error analysis
    if analysis['events']['errors']:
        print(f"\n❌ Error Analysis:")
        print("-" * 30)
        error_counts = Counter(error['step'] for error in analysis['events']['errors'])
        for step, count in error_counts.most_common():
            print(f"  {step:20} {count:3d} errors")
        
        print(f"\n🔍 Recent Errors:")
        print("-" * 30)
        recent_errors = sorted(analysis['events']['errors'], 
                             key=lambda x: x['timestamp'], reverse=True)[:5]
        for error in recent_errors:
            timestamp = error['timestamp'][:19]  # YYYY-MM-DD HH:MM:SS
            print(f"  {timestamp} - {error['step']}: {error['error'][:60]}...")
    
    # Recent runs
    print(f"\n🕒 Recent Runs:")
    print("-" * 30)
    recent_runs = sorted(analysis['runs'], 
                        key=lambda x: x.get('run_name', ''), reverse=True)[:10]
    for run in recent_runs:
        status = "✅" if run.get('workflow_success', False) else "❌"
        duration = run.get('duration_seconds', 0)
        messages = run.get('messages_extracted', 0)
        print(f"  {status} {run['run_name']:30} {duration:6.1f}s {messages:4d} msgs")
    
    print("\n" + "="*80)

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze run logs from NAS log analysis workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all run logs in default directory
  python3 analyze_run_logs.py
  
  # Analyze run logs in specific directory
  python3 analyze_run_logs.py data/analysis_results/
  
  # Analyze run logs and save report
  python3 analyze_run_logs.py data/analysis_results/ > run_analysis_report.txt
        """
    )
    
    parser.add_argument('log_directory', nargs='?', default='data/analysis_results/',
                       help='Directory containing run logs (default: data/analysis_results/)')
    parser.add_argument('--output', '-o', help='Output file for analysis report')
    
    args = parser.parse_args()
    
    # Load run logs
    print(f"🔍 Loading run logs from: {args.log_directory}")
    run_logs = load_run_logs(args.log_directory)
    
    if not run_logs:
        print(f"❌ No run logs found in {args.log_directory}")
        print("💡 Make sure you have run the analysis workflow at least once.")
        sys.exit(1)
    
    print(f"✅ Loaded {len(run_logs)} run logs")
    
    # Analyze run logs
    print("📊 Analyzing run logs...")
    analysis = analyze_run_logs(run_logs)
    
    # Print or save report
    if args.output:
        with open(args.output, 'w') as f:
            # Redirect stdout to file
            import sys
            original_stdout = sys.stdout
            sys.stdout = f
            print_analysis_report(analysis)
            sys.stdout = original_stdout
        print(f"✅ Analysis report saved to: {args.output}")
    else:
        print_analysis_report(analysis)

if __name__ == '__main__':
    main() 