"""Data grouping module for NAS Log Processing System."""

import pandas as pd
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
import structlog

from ..utils.file_handler import read_csv_safe, write_csv_safe, ensure_directory

logger = structlog.get_logger(__name__)


def load_procedure_map(config_path: Optional[str] = None) -> Dict[str, str]:
    """
    Load procedure mapping from YAML config.
    Returns a dict mapping message_type to procedure.
    """
    if config_path is None:
        config_path = Path(__file__).parent.parent / "config" / "procedure_map.yaml"
    config_path = Path(config_path)
    if not config_path.exists():
        logger.warning("Procedure map config not found, using empty map", config_path=str(config_path))
        return {}
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    proc_map = {}
    for proc, entry in config.get("procedures", {}).items():
        for msg in entry.get("messages", []):
            proc_map[msg] = proc
    return proc_map


class DataGrouper:
    """
    Groups NAS events by procedure, message_type, session, or direction.
    """
    def __init__(self, procedure_map_path: Optional[str] = None):
        self.procedure_map = load_procedure_map(procedure_map_path)

    def group(self, df: pd.DataFrame, strategies: List[str]) -> Dict[str, pd.DataFrame]:
        grouped = {}
        if 'procedure' in strategies:
            df['procedure'] = df['message_type'].map(self.procedure_map).fillna('Other')
            for proc, group_df in df.groupby('procedure'):
                grouped[f'procedure_{proc.replace(" ", "_")}'] = group_df
        if 'message_type' in strategies:
            for msg_type, group_df in df.groupby('message_type'):
                if msg_type:
                    grouped[f'msgtype_{msg_type.replace(" ", "_")}'] = group_df
        if 'session' in strategies:
            df['session_key'] = df['guti'].fillna('') + '_' + df['bearer_id'].fillna('')
            for session_key, group_df in df.groupby('session_key'):
                if session_key and session_key != '_':
                    grouped[f'session_{session_key}'] = group_df
        if 'direction' in strategies:
            for direction, group_df in df.groupby('direction'):
                if direction:
                    grouped[f'direction_{direction}'] = group_df
        return grouped

    def write_grouped(self, grouped: Dict[str, pd.DataFrame], output_dir: str) -> List[str]:
        ensure_directory(output_dir)
        output_files = []
        for name, group_df in grouped.items():
            out_file = Path(output_dir) / f"{name}.csv"
            write_csv_safe(group_df, out_file)
            output_files.append(str(out_file))
            logger.info("Wrote grouped file", file=str(out_file), rows=len(group_df))
        return output_files 