#!/usr/bin/env python3
"""
Container Visualization CLI
Command-line interface for generating container analysis visualizations
"""

import argparse
import json
import pandas as pd
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.visualization.container_visualizer import ContainerVisualizer
from src.core.enhanced_parser import EnhancedNASParser

def main():
    parser = argparse.ArgumentParser(description='Generate container analysis visualizations')
    parser.add_argument('-i', '--input', required=True, help='Input NAS log file')
    parser.add_argument('-o', '--output-dir', default='data/visualizations', 
                       help='Output directory for visualizations')
    parser.add_argument('--csv-file', help='Use existing CSV file instead of parsing')
    parser.add_argument('--analysis-file', help='Use existing analysis JSON file')
    parser.add_argument('--all', action='store_true', help='Generate all visualizations')
    parser.add_argument('--summary', action='store_true', help='Generate summary chart')
    parser.add_argument('--timeline', action='store_true', help='Generate timeline chart')
    parser.add_argument('--bearer', action='store_true', help='Generate bearer analysis')
    parser.add_argument('--protocol', action='store_true', help='Generate protocol analysis')
    parser.add_argument('--report', action='store_true', help='Generate detailed HTML report')
    
    args = parser.parse_args()
    
    # Initialize visualizer
    visualizer = ContainerVisualizer(args.output_dir)
    
    # Load or generate analysis data
    if args.analysis_file:
        with open(args.analysis_file, 'r') as f:
            analysis_data = json.load(f)
    else:
        print("🔄 Running enhanced parser to generate analysis data...")
        parser = EnhancedNASParser()
        analysis_data = parser.parse_log(args.input, f"{args.output_dir}/temp_analysis.json")
    
    # Load or generate CSV data
    if args.csv_file:
        csv_data = pd.read_csv(args.csv_file)
    else:
        print("🔄 Loading CSV data...")
        # Use the enhanced CSV we generated earlier
        csv_file = f"{args.output_dir}/../enhanced_analysis_containers/NAS_speed_test_06-02.15-53-27-127_enhanced_fixed.csv"
        if Path(csv_file).exists():
            csv_data = pd.read_csv(csv_file)
        else:
            print(f"❌ CSV file not found: {csv_file}")
            return 1
    
    print("📊 Generating visualizations...")
    
    results = {}
    
    # Generate requested visualizations
    if args.all or args.summary:
        print("📈 Generating container summary chart...")
        results['summary'] = visualizer.create_container_summary_chart(analysis_data)
    
    if args.all or args.timeline:
        print("⏰ Generating timeline chart...")
        results['timeline'] = visualizer.create_timeline_chart(csv_data)
    
    if args.all or args.bearer:
        print("📡 Generating bearer analysis...")
        results['bearer'] = visualizer.create_bearer_analysis_chart(csv_data)
    
    if args.all or args.protocol:
        print("🌐 Generating protocol analysis...")
        results['protocol'] = visualizer.create_protocol_analysis_chart(analysis_data)
    
    if args.all or args.report:
        print("📋 Generating detailed HTML report...")
        results['report'] = visualizer.create_detailed_container_report(analysis_data, csv_data)
    
    # If no specific charts requested, generate all
    if not any([args.all, args.summary, args.timeline, args.bearer, args.protocol, args.report]):
        print("🎨 Generating all visualizations...")
        results = visualizer.generate_all_visualizations(analysis_data, csv_file)
    
    # Print results
    print("\n✅ Visualization generation completed!")
    print("📁 Generated files:")
    for chart_type, file_path in results.items():
        if file_path:
            print(f"   • {chart_type}: {file_path}")
    
    print(f"\n📂 All visualizations saved to: {args.output_dir}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 