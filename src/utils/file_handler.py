"""File handling utilities for NAS Log Processing System."""

import csv
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import pandas as pd
import structlog

logger = structlog.get_logger(__name__)


def ensure_directory(path: Union[str, Path]) -> Path:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        path: Directory path
    
    Returns:
        Path object for the directory
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_csv_safe(file_path: Union[str, Path]) -> pd.DataFrame:
    """
    Safely read a CSV file with error handling.
    
    Args:
        file_path: Path to CSV file
    
    Returns:
        DataFrame containing the CSV data
    
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file is empty or malformed
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if file_path.stat().st_size == 0:
        raise ValueError(f"File is empty: {file_path}")
    
    try:
        df = pd.read_csv(file_path)
        logger.info(f"Successfully read CSV file", file=str(file_path), rows=len(df))
        return df
    except Exception as e:
        logger.error(f"Error reading CSV file", file=str(file_path), error=str(e))
        raise


def write_csv_safe(
    data: Union[pd.DataFrame, List[Dict[str, Any]]],
    file_path: Union[str, Path],
    index: bool = False
) -> None:
    """
    Safely write data to a CSV file with error handling.
    
    Args:
        data: DataFrame or list of dictionaries to write
        file_path: Output file path
        index: Whether to write DataFrame index
    """
    file_path = Path(file_path)
    
    # Ensure directory exists
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        if isinstance(data, list):
            # Convert list of dicts to DataFrame
            df = pd.DataFrame(data)
        else:
            df = data
        
        df.to_csv(file_path, index=index)
        logger.info(f"Successfully wrote CSV file", file=str(file_path), rows=len(df))
    except Exception as e:
        logger.error(f"Error writing CSV file", file=str(file_path), error=str(e))
        raise


def write_json_safe(
    data: Dict[str, Any],
    file_path: Union[str, Path],
    indent: int = 2
) -> None:
    """
    Safely write data to a JSON file with error handling.
    
    Args:
        data: Dictionary to write
        file_path: Output file path
        indent: JSON indentation
    """
    file_path = Path(file_path)
    
    # Ensure directory exists
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=indent)
        logger.info(f"Successfully wrote JSON file", file=str(file_path))
    except Exception as e:
        logger.error(f"Error writing JSON file", file=str(file_path), error=str(e))
        raise


def get_file_size_mb(file_path: Union[str, Path]) -> float:
    """
    Get file size in megabytes.
    
    Args:
        file_path: Path to file
    
    Returns:
        File size in MB
    """
    file_path = Path(file_path)
    if not file_path.exists():
        return 0.0
    
    size_bytes = file_path.stat().st_size
    return size_bytes / (1024 * 1024)


def validate_file_format(file_path: Union[str, Path], expected_extension: str) -> bool:
    """
    Validate file format based on extension.
    
    Args:
        file_path: Path to file
        expected_extension: Expected file extension (e.g., '.txt', '.csv')
    
    Returns:
        True if file has expected format
    """
    file_path = Path(file_path)
    return file_path.suffix.lower() == expected_extension.lower()


def backup_file(file_path: Union[str, Path], backup_suffix: str = ".backup") -> Path:
    """
    Create a backup of a file.
    
    Args:
        file_path: Path to file to backup
        backup_suffix: Suffix for backup file
    
    Returns:
        Path to backup file
    """
    file_path = Path(file_path)
    backup_path = file_path.with_suffix(file_path.suffix + backup_suffix)
    
    if file_path.exists():
        import shutil
        shutil.copy2(file_path, backup_path)
        logger.info(f"Created backup file", original=str(file_path), backup=str(backup_path))
    
    return backup_path


def get_file_info(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Get comprehensive file information.
    
    Args:
        file_path: Path to file
    
    Returns:
        Dictionary with file information
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        return {"exists": False}
    
    stat = file_path.stat()
    
    return {
        "exists": True,
        "size_bytes": stat.st_size,
        "size_mb": stat.st_size / (1024 * 1024),
        "modified": stat.st_mtime,
        "extension": file_path.suffix,
        "name": file_path.name,
        "parent": str(file_path.parent)
    } 