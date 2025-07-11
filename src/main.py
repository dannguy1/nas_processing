"""Main CLI entry point for NAS Log Processing System."""

import click
from pathlib import Path
import structlog
import os

from .utils.logger import setup_logger
from .core.parser import NASParser
from .core.grouper import DataGrouper
from .core.analyzer import AdvancedAnalyzer
from .utils.file_handler import read_csv_safe

logger = structlog.get_logger(__name__)


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--log-file', type=click.Path(), help='Log file path')
def cli(verbose: bool, log_file: str):
    """3GPP NAS Log Processing System
    
    A comprehensive system for parsing, analyzing, and troubleshooting 3GPP NAS logs
    with AI/ML capabilities for field technicians.
    """
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    log_path = Path(log_file) if log_file else None
    
    setup_logger(
        name="nas_processing",
        level=log_level,
        log_file=log_path,
        console_output=True
    )
    
    logger.info("NAS Processing System started", verbose=verbose, log_file=log_file)


@cli.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True), help='Input log file')
@click.option('--output', '-o', required=True, type=click.Path(), help='Output CSV file')
@click.option('--config', '-c', type=click.Path(), help='Configuration file path')
def parse(input: str, output: str, config: str):
    """Parse NAS log file and extract structured data."""
    try:
        logger.info("Starting log parsing", input=input, output=output, config=config)
        
        parser = NASParser(config_path=config)
        stats = parser.parse_log(input, output)
        
        click.echo(f"✅ Parsing completed successfully!")
        click.echo(f"📊 Statistics:")
        click.echo(f"   - Input file: {stats['input_file']}")
        click.echo(f"   - Output file: {stats['output_file']}")
        click.echo(f"   - Total lines processed: {stats['total_lines']:,}")
        click.echo(f"   - Messages extracted: {stats['messages_extracted']:,}")
        click.echo(f"   - Validation errors: {stats['validation_errors']}")
        click.echo(f"   - File size: {stats['file_size_mb']:.2f} MB")
        
    except Exception as e:
        logger.error("Parsing failed", error=str(e))
        click.echo(f"❌ Error: {e}")
        raise click.Abort()


@cli.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True), help='Input CSV file')
@click.option('--output-dir', '-o', required=True, type=click.Path(), help='Output directory')
@click.option('--group-by', '-g', multiple=True, 
              type=click.Choice(['procedure', 'message_type', 'session', 'direction']),
              default=['procedure'], help='Grouping strategies')
@click.option('--procedure-map', type=click.Path(), help='Procedure map YAML file')
def group(input: str, output_dir: str, group_by: tuple, procedure_map: str):
    """Group parsed data by various criteria."""
    try:
        logger.info("Starting grouping", input=input, output_dir=output_dir, group_by=group_by, procedure_map=procedure_map)
        df = read_csv_safe(input)
        grouper = DataGrouper(procedure_map_path=procedure_map)
        grouped = grouper.group(df, list(group_by))
        output_files = grouper.write_grouped(grouped, output_dir)
        click.echo(f"✅ Grouping completed. {len(output_files)} files written to {output_dir}")
        for f in output_files:
            click.echo(f" - {f}")
    except Exception as e:
        logger.error("Grouping failed", error=str(e))
        click.echo(f"❌ Error: {e}")
        raise click.Abort()


@cli.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True), help='Input CSV file with parsed messages')
@click.option('--output-dir', '-o', required=True, type=click.Path(), help='Output directory for analysis results')
@click.option('--formats', '-f', multiple=True, 
              type=click.Choice(['csv', 'json', 'excel', 'html', 'pdf']),
              default=['csv'], help='Output formats')
@click.option('--correlate', is_flag=True, help='Correlate related messages')
@click.option('--sequence-diagram', is_flag=True, help='Generate a sequence diagram (Mermaid.js HTML)')
@click.option('--timeline', is_flag=True, help='Generate interactive timeline visualizations (Plotly HTML)')
def analyze(input: str, output_dir: str, formats: tuple, correlate: bool, sequence_diagram: bool, timeline: bool):
    """Perform advanced analysis on parsed NAS messages."""
    try:
        logger.info("Starting advanced analysis", input=input, output_dir=output_dir, formats=formats, correlate=correlate, sequence_diagram=sequence_diagram, timeline=timeline)
        
        # Read the parsed messages
        df = read_csv_safe(input)
        
        # Get original input file name from environment variable
        original_input_file = os.environ.get('ORIGINAL_INPUT_FILE', None)
        
        # Perform analysis
        analyzer = AdvancedAnalyzer()
        output_files = analyzer.analyze_messages(df, output_dir, list(formats), 
                                               generate_sequence_diagram=sequence_diagram, 
                                               generate_timeline=timeline,
                                               input_file=original_input_file)
        
        click.echo(f"✅ Analysis completed successfully!")
        click.echo(f"📊 Analysis Results:")
        click.echo(f"   - Input file: {input}")
        click.echo(f"   - Output directory: {output_dir}")
        click.echo(f"   - Messages analyzed: {len(df):,}")
        click.echo(f"   - Output formats: {', '.join(formats)}")
        click.echo(f"   - Output files:")
        for format_type, file_path in output_files.items():
            click.echo(f"     - {format_type}: {file_path}")
        if 'sequence_diagram' in output_files:
            click.echo(f"     - sequence_diagram: {output_files['sequence_diagram']}")
        if 'timeline' in output_files:
            click.echo(f"     - timeline: {output_files['timeline']}")
        if 'detailed_timeline' in output_files:
            click.echo(f"     - detailed_timeline: {output_files['detailed_timeline']}")
        
    except Exception as e:
        logger.error("Analysis failed", error=str(e))
        click.echo(f"❌ Error: {e}")
        raise click.Abort()


@cli.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True), help='Input CSV file')
@click.option('--output', '-o', type=click.Path(), help='Output HTML file')
def visualize(input: str, output: str):
    """Create visualizations of parsed data."""
    click.echo(f"📊 Visualization functionality coming soon!")
    click.echo(f"Input: {input}")
    click.echo(f"Output: {output}")


@cli.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True), help='Input CSV file with parsed messages')
@click.option('--output', '-o', required=True, type=click.Path(), help='Output CSV file with decoded APN names')
def decode_apn(input: str, output: str):
    """Decode APN names from ASCII values in parsed messages."""
    try:
        logger.info("Starting APN decoding", input=input, output=output)
        
        # Read the parsed messages
        df = read_csv_safe(input)
        
        # Decode APN names
        from .core.analyzer import APNDecoder
        decoder = APNDecoder()
        enhanced_df = decoder.enhance_messages_with_apn(df)
        
        # Save enhanced data
        enhanced_df.to_csv(output, index=False)
        
        # Count decoded APNs
        decoded_count = len(enhanced_df[enhanced_df['decoded_apn'] != ''])
        
        click.echo(f"✅ APN decoding completed successfully!")
        click.echo(f"📊 Results:")
        click.echo(f"   - Input file: {input}")
        click.echo(f"   - Output file: {output}")
        click.echo(f"   - Messages processed: {len(df):,}")
        click.echo(f"   - APN names decoded: {decoded_count:,}")
        
        if decoded_count > 0:
            click.echo(f"   - Sample decoded APNs:")
            sample_apns = enhanced_df[enhanced_df['decoded_apn'] != '']['decoded_apn'].head(5).tolist()
            for apn in sample_apns:
                click.echo(f"     - {apn}")
        
    except Exception as e:
        logger.error("APN decoding failed", error=str(e))
        click.echo(f"❌ Error: {e}")
        raise click.Abort()


@cli.command()
def version():
    """Show version information."""
    from . import __version__
    click.echo(f"NAS Log Processing System v{__version__}")


if __name__ == '__main__':
    cli() 