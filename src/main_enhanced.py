#!/usr/bin/env python3
"""Enhanced NAS Log Parser with YAML Message Definition Integration."""

import click
import sys
from pathlib import Path
import structlog

from core.enhanced_parser import EnhancedNASParser
from core.message_definitions import MessageDefinitionLoader
from utils.logger import setup_logging

logger = structlog.get_logger(__name__)


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--log-file', type=click.Path(), help='Log file path')
def cli(verbose, log_file):
    """Enhanced NAS Log Parser with YAML Message Definition Integration."""
    setup_logging(verbose=verbose, log_file=log_file)


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('--config', '-c', type=click.Path(), help='Field mappings configuration file')
@click.option('--lte-spec', type=click.Path(), help='LTE specification YAML file')
@click.option('--nr-spec', type=click.Path(), help='5G NR specification YAML file')
@click.option('--enhanced-only', is_flag=True, help='Generate only enhanced output')
def parse(input_file, output_file, config, lte_spec, nr_spec, enhanced_only):
    """Parse NAS log file with enhanced YAML definition integration."""
    try:
        # Initialize enhanced parser
        parser = EnhancedNASParser(
            config_path=config,
            lte_spec_path=lte_spec,
            nr_spec_path=nr_spec
        )
        
        logger.info("Starting enhanced parsing", 
                   input=input_file, 
                   output=output_file,
                   enhanced_only=enhanced_only)
        
        # Parse with enhanced features
        result = parser.parse_log(input_file, output_file)
        
        # Print summary
        print("\n=== Enhanced NAS Parsing Results ===")
        print(f"Input file: {input_file}")
        print(f"Output file: {output_file}")
        print(f"Enhanced output: {result.get('enhanced_output', 'N/A')}")
        print(f"Total messages: {result.get('message_count', 0)}")
        print(f"Enhanced records: {len(result.get('enhanced_records', []))}")
        
        # Print analysis summary
        analysis = result.get('analysis_report', {})
        if analysis:
            print(f"\nTechnology distribution: {analysis.get('technology_distribution', {})}")
            print(f"Procedure distribution: {analysis.get('procedure_distribution', {})}")
            print(f"Definition coverage: {analysis.get('definition_coverage_percent', 0):.1f}%")
            print(f"Enhanced fields extracted: {analysis.get('enhanced_fields_extracted', 0)}")
        
        logger.info("Enhanced parsing completed successfully")
        
    except Exception as e:
        logger.error("Enhanced parsing failed", error=str(e))
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_dir', type=click.Path())
@click.option('--config', '-c', type=click.Path(), help='Field mappings configuration file')
@click.option('--lte-spec', type=click.Path(), help='LTE specification YAML file')
@click.option('--nr-spec', type=click.Path(), help='5G NR specification YAML file')
def analyze(input_file, output_dir, config, lte_spec, nr_spec):
    """Generate comprehensive analysis with procedure reports."""
    try:
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize enhanced parser
        parser = EnhancedNASParser(
            config_path=config,
            lte_spec_path=lte_spec,
            nr_spec_path=nr_spec
        )
        
        logger.info("Starting comprehensive analysis", 
                   input=input_file, 
                   output_dir=output_dir)
        
        # Export enhanced analysis
        summary = parser.export_enhanced_analysis(input_file, output_dir)
        
        # Print summary
        print("\n=== Comprehensive Analysis Results ===")
        print(f"Input file: {input_file}")
        print(f"Output directory: {output_dir}")
        print(f"Total messages: {summary.get('total_messages', 0)}")
        print(f"Analysis report: {summary.get('procedure_report_file', 'N/A')}")
        print(f"Summary file: {summary.get('summary_file', 'N/A')}")
        
        # Print analysis highlights
        analysis = summary.get('analysis_report', {})
        if analysis:
            print(f"\nTechnology distribution: {analysis.get('technology_distribution', {})}")
            print(f"Procedure distribution: {analysis.get('procedure_distribution', {})}")
            print(f"Definition coverage: {analysis.get('definition_coverage_percent', 0):.1f}%")
        
        logger.info("Comprehensive analysis completed successfully")
        
    except Exception as e:
        logger.error("Comprehensive analysis failed", error=str(e))
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--lte-spec', type=click.Path(), help='LTE specification YAML file')
@click.option('--nr-spec', type=click.Path(), help='5G NR specification YAML file')
def validate(input_file, lte_spec, nr_spec):
    """Validate YAML message definitions against log file."""
    try:
        # Initialize message loader
        loader = MessageDefinitionLoader(lte_spec, nr_spec)
        
        logger.info("Starting YAML definition validation", input=input_file)
        
        # Load and parse the log file to get message types
        parser = EnhancedNASParser()
        result = parser.parse_log(input_file, "/tmp/validation_temp.csv")
        
        # Analyze definition coverage
        records = result.get('enhanced_records', [])
        total_messages = len(records)
        defined_messages = sum(1 for r in records if r.get('definition_found', False))
        
        # Technology breakdown
        lte_messages = sum(1 for r in records if r.get('technology') == 'LTE')
        nr_messages = sum(1 for r in records if r.get('technology') == '5G')
        
        # Procedure breakdown
        procedures = {}
        for record in records:
            proc = record.get('procedure', 'Unknown')
            procedures[proc] = procedures.get(proc, 0) + 1
        
        # Print validation results
        print("\n=== YAML Definition Validation Results ===")
        print(f"Input file: {input_file}")
        print(f"Total messages: {total_messages}")
        print(f"Messages with definitions: {defined_messages}")
        print(f"Definition coverage: {(defined_messages/total_messages)*100:.1f}%" if total_messages > 0 else "0%")
        print(f"\nTechnology breakdown:")
        print(f"  LTE messages: {lte_messages}")
        print(f"  5G messages: {nr_messages}")
        print(f"  Unknown: {total_messages - lte_messages - nr_messages}")
        
        print(f"\nProcedure breakdown:")
        for proc, count in sorted(procedures.items(), key=lambda x: x[1], reverse=True):
            print(f"  {proc}: {count}")
        
        # Show missing definitions
        undefined_messages = set()
        for record in records:
            if not record.get('definition_found', False):
                undefined_messages.add(record.get('message_type', ''))
        
        if undefined_messages:
            print(f"\nMessages without definitions:")
            for msg in sorted(undefined_messages):
                print(f"  - {msg}")
        
        logger.info("YAML definition validation completed")
        
    except Exception as e:
        logger.error("YAML definition validation failed", error=str(e))
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('lte_spec', type=click.Path(exists=True))
@click.argument('nr_spec', type=click.Path(exists=True))
def info(lte_spec, nr_spec):
    """Display information about loaded YAML specifications."""
    try:
        # Initialize message loader
        loader = MessageDefinitionLoader(lte_spec, nr_spec)
        
        print("\n=== YAML Specification Information ===")
        print(f"LTE specification: {lte_spec}")
        print(f"5G NR specification: {nr_spec}")
        
        # LTE messages
        lte_messages = loader.lte_messages.get('messages', [])
        print(f"\nLTE Messages ({len(lte_messages)}):")
        for msg in lte_messages:
            print(f"  {msg['name']} (0x{msg['hex_code']}) - {msg['procedure']}")
        
        # 5G messages
        nr_messages = loader.nr_messages.get('messages', [])
        print(f"\n5G NR Messages ({len(nr_messages)}):")
        for msg in nr_messages:
            print(f"  {msg['name']} (0x{msg['hex_code']}) - {msg['procedure']}")
        
        # Procedure summary
        lte_procedures = set(msg['procedure'] for msg in lte_messages)
        nr_procedures = set(msg['procedure'] for msg in nr_messages)
        
        print(f"\nLTE Procedures ({len(lte_procedures)}): {', '.join(sorted(lte_procedures))}")
        print(f"5G Procedures ({len(nr_procedures)}): {', '.join(sorted(nr_procedures))}")
        
        logger.info("YAML specification information displayed")
        
    except Exception as e:
        logger.error("Failed to display YAML specification information", error=str(e))
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli() 