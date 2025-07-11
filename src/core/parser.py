"""Enhanced NAS log parser with configuration-driven field extraction."""

import re
import csv
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import pandas as pd
import structlog

from ..utils.logger import PerformanceLogger
from ..utils.file_handler import write_csv_safe, get_file_info
from .validator import create_validator_from_config

logger = structlog.get_logger(__name__)


class NASParser:
    """Enhanced NAS Log Parser with robust message extraction and field parsing."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize parser with configuration."""
        self.config = self._load_config(config_path)
        self.validators = self._setup_validators()
        self.compiled_patterns = self._compile_patterns()
        self.fieldnames = list(self.config.keys())
        
        logger.info("NAS Parser initialized", config_path=config_path, fields=len(self.fieldnames))
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Dict]:
        """Load field mappings configuration."""
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "field_mappings.yaml"
        
        config_path = Path(config_path)
        
        if not config_path.exists():
            logger.warning(f"Config file not found, using default patterns", config_path=str(config_path))
            return self._get_default_config()
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_path}", fields=len(config))
            return config
        except Exception as e:
            logger.error(f"Error loading config, using defaults", error=str(e))
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Dict]:
        """Get default field configuration based on sample code patterns."""
        return {
            "timestamp": {
                "patterns": [r"^(\d{4} \w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3})"],
                "validation": {"required": True, "format": "datetime"}
            },
            "direction": {
                "patterns": [
                    r"LTE NAS.*Plain OTA.*(Incoming|Outgoing).*Message.*--",
                    r"LTE NAS.*Security Protected.*(Incoming|Outgoing).*Msg",
                    r"LTE NAS.*(Incoming|Outgoing).*Message.*--"
                ],
                "validation": {"required": True, "allowed_values": ["Incoming", "Outgoing"]}
            },
            "message_type": {
                "patterns": [
                    r"LTE NAS.*(?:Plain )?OTA.*(Incoming|Outgoing).*Message.*--\s*(.+?)(?:\s+Msg)?$",
                    r"LTE NAS.*Security Protected.*(Incoming|Outgoing).*Msg",
                    r"LTE NAS.*State",
                    r"LTE NAS.*Bearer Context.*State",
                    r"LTE NAS.*Bearer Context.*Info",
                    r"LTE NAS.*Procedure.*State"
                ],
                "validation": {"required": True}
            },
            "bearer_id": {
                "patterns": [r"Bearer ID = (\d+)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "apn": {
                "patterns": [
                    r"acc_pt_name_val\[\d+\] = \d+ \(.+\) \((.+)\)",
                    r"access_point_name.*?acc_pt_name_val\[\d+\] = \d+ \(.+\) \((.+)\)"
                ],
                "validation": {"required": False, "min_length": 1}
            },
            "ipv4": {
                "patterns": [
                    r"ipv4_addr = \d+ \(0x[0-9a-fA-F]+\) \(([\d\.]+)\)",
                    r"ipv4_addr = (\d+) \(0x[0-9a-fA-F]+\) \(([ 0-9\.]+)\)"
                ],
                "validation": {"required": False, "format": "ipv4"}
            },
            "qci": {
                "patterns": [
                    r"qci = (\d+)",
                    r"qci = (\d+) \(0x[0-9a-fA-F]+\) \(QC\d+\)"
                ],
                "validation": {"required": False, "data_type": "integer", "range": [1, 9]}
            },
            "mcc": {
                "patterns": [
                    r"mcc_1 = (\d+).*mcc_2 = (\d+).*mcc_3 = (\d+)",
                    r"MCC digit 1 = (\d+).*MCC digit 2 = (\d+).*MCC digit 3 = (\d+)"
                ],
                "validation": {"required": False, "data_type": "string", "length": 3}
            },
            "mnc": {
                "patterns": [
                    r"mnc_1 = (\d+).*mnc_2 = (\d+).*mnc_3 = (\d+)",
                    r"MNC digit 1 = (\d+).*MNC digit 2 = (\d+).*MNC digit 3 = (\d+)"
                ],
                "validation": {"required": False, "data_type": "string", "length": 3}
            },
            "guti": {
                "patterns": [
                    r"id_type = \d+.*GUTI",
                    r"Guti valid = True"
                ],
                "validation": {"required": False, "allowed_values": ["yes", ""]}
            },
            "mme_group_id": {
                "patterns": [
                    r"MME_group_id = (\d+) \(0x[0-9a-fA-F]+\)",
                    r"MME Group Id = \{ (\d+), (\d+) \}"
                ],
                "validation": {"required": False, "data_type": "integer"}
            },
            "mme_code": {
                "patterns": [
                    r"MME_code = (\d+) \(0x[0-9a-fA-F]+\)",
                    r"MME Code = (\d+)"
                ],
                "validation": {"required": False, "data_type": "integer"}
            },
            "tmsi": {
                "patterns": [
                    r"m_tmsi = (\d+) \(0x[0-9a-fA-F]+\)",
                    r"M TMSI = (\d+) \(0x[0-9a-fA-F]+\)"
                ],
                "validation": {"required": False, "data_type": "integer"}
            },
            "nas_key_set_id": {
                "patterns": [r"nas_key_set_id = (\d+)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "att_type": {
                "patterns": [r"att_type = (\d+).*?\((.*?)\)"],
                "validation": {"required": False}
            },
            "tsc": {
                "patterns": [r"tsc = (\d+)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "eea": {
                "patterns": [r"(EEA\d+(_128)?) = (\d+)"],
                "validation": {"required": False}
            },
            "eia": {
                "patterns": [r"(EIA\d+(_128)?) = (\d+)"],
                "validation": {"required": False}
            },
            "uea": {
                "patterns": [r"(UEA\d+) = (\d+)"],
                "validation": {"required": False}
            },
            # New fields for enhanced analysis
            "emm_state": {
                "patterns": [r"EMM state = (.+)"],
                "validation": {"required": False}
            },
            "emm_sub_state": {
                "patterns": [r"EMM sub-state = (.+)"],
                "validation": {"required": False}
            },
            "bearer_state": {
                "patterns": [r"Bearer State = (.+)"],
                "validation": {"required": False}
            },
            "procedure_state": {
                "patterns": [r"Procedure State = (.+)"],
                "validation": {"required": False}
            },
            "pti": {
                "patterns": [r"PTI = (\d+)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "sdf_id": {
                "patterns": [r"SDF ID = (\d+)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "connection_id": {
                "patterns": [r"Connection ID = (\d+)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "rb_id": {
                "patterns": [r"RB ID = (\d+)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "apn_ambr_dl": {
                "patterns": [r"apn_ambr_dl = (\d+) \(0x[0-9a-fA-F]+\) \(([^)]+)\)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "apn_ambr_ul": {
                "patterns": [r"apn_ambr_ul = (\d+) \(0x[0-9a-fA-F]+\) \(([^)]+)\)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "pdn_type": {
                "patterns": [r"pdn_type = (\d+).*?\(([^)]+)\)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "req_type": {
                "patterns": [r"req_type = (\d+).*?\(([^)]+)\)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "trans_id": {
                "patterns": [r"Trans Id = (\d+)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "version": {
                "patterns": [r"Version = (\d+)"],
                "validation": {"required": False, "data_type": "integer"}
            },
            "subscription_id": {
                "patterns": [r"Subscription ID = (\d+)"],
                "validation": {"required": False, "data_type": "integer"}
            }
        }
    
    def _setup_validators(self) -> Dict[str, Any]:
        """Set up validators for each field."""
        return create_validator_from_config(self.config)
    
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for efficient matching."""
        compiled_patterns = {}
        
        for field_name, field_config in self.config.items():
            if "patterns" in field_config:
                patterns = []
                for pattern_str in field_config["patterns"]:
                    try:
                        patterns.append(re.compile(pattern_str, re.DOTALL))
                    except re.error as e:
                        logger.warning(f"Invalid regex pattern for {field_name}", pattern=pattern_str, error=str(e))
                compiled_patterns[field_name] = patterns
        
        return compiled_patterns
    
    def parse_log(self, input_file: str, output_file: str) -> Dict[str, Any]:
        """
        Parse NAS log file and extract structured data.
        
        Args:
            input_file: Path to input log file
            output_file: Path to output CSV file
        
        Returns:
            Dictionary with parsing statistics
        """
        input_path = Path(input_file)
        output_path = Path(output_file)
        
        # Validate input file
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        file_info = get_file_info(input_path)
        logger.info("Starting log parsing", input_file=str(input_path), file_size_mb=file_info.get("size_mb", 0))
        
        with PerformanceLogger(logger, "log parsing"):
            records = []
            current_record = {field: "" for field in self.fieldnames}
            in_msg = False
            in_emm_attach = False
            eea_list = []
            eia_list = []
            uea_list = []
            
            line_count = 0
            message_count = 0
            error_count = 0
            
            try:
                with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
                    last_timestamp = ""
                    current_message_lines = []
                    current_message_started = False
                    
                    for line in f:
                        line_count += 1
                        
                        # Check for timestamp (new message)
                        ts_match = self._extract_timestamp(line)
                        if ts_match:
                            # Check if this line also contains a message type
                            msg_match = self._extract_message_info(line)
                            
                            # If we have a previous message, write it
                            if in_msg and current_record["message_type"]:
                                # Process the complete message block
                                self._process_message_block(current_message_lines, current_record, eea_list, eia_list, uea_list)
                                if self._validate_and_add_record(current_record, records):
                                    message_count += 1
                                else:
                                    error_count += 1
                            
                            # Start new message if this line contains a message type
                            if msg_match:
                                current_record = {field: "" for field in self.fieldnames}
                                current_record["timestamp"] = ts_match
                                current_record["direction"] = msg_match[0]
                                current_record["message_type"] = msg_match[1].strip()
                                current_message_lines = [line]
                                current_message_started = True
                                in_msg = True
                                in_emm_attach = False
                                eea_list = []
                                eia_list = []
                                uea_list = []
                            else:
                                # Just a timestamp line, continue with current message if exists
                                if in_msg:
                                    current_message_lines.append(line)
                                else:
                                    # Start a new message block with just timestamp
                                    current_record = {field: "" for field in self.fieldnames}
                                    current_record["timestamp"] = ts_match
                                    current_message_lines = [line]
                                    current_message_started = False
                                    in_msg = False
                                    in_emm_attach = False
                                    eea_list = []
                                    eia_list = []
                                    uea_list = []
                        else:
                            # Check for message type in non-timestamp lines
                            msg_match = self._extract_message_info(line)
                            if msg_match and not current_message_started:
                                # Start a new message
                                if not current_record["timestamp"] and last_timestamp:
                                    current_record["timestamp"] = last_timestamp
                                current_record["direction"] = msg_match[0]
                                current_record["message_type"] = msg_match[1].strip()
                                current_message_lines.append(line)
                                current_message_started = True
                                in_msg = True
                                in_emm_attach = False
                                eea_list = []
                                eia_list = []
                                uea_list = []
                            elif in_msg:
                                # Continue current message
                                current_message_lines.append(line)
                            elif current_message_lines:
                                # Add to current message block even if not started
                                current_message_lines.append(line)
                        
                        # Update last timestamp
                        if ts_match:
                            last_timestamp = ts_match
                        
                        # Check for end of message (next timestamp with message type or significant gap)
                        if in_msg and ts_match:
                            # Check if this timestamp line contains a message type
                            next_msg_match = self._extract_message_info(line)
                            if next_msg_match:
                                # This is a new message, write the previous one
                                if current_record["message_type"]:
                                    # Process the complete message block
                                    self._process_message_block(current_message_lines, current_record, eea_list, eia_list, uea_list)
                                    if self._validate_and_add_record(current_record, records):
                                        message_count += 1
                                    else:
                                        error_count += 1
                                
                                # Start new message
                                current_record = {field: "" for field in self.fieldnames}
                                current_record["timestamp"] = ts_match
                                current_record["direction"] = next_msg_match[0]
                                current_record["message_type"] = next_msg_match[1].strip()
                                current_message_lines = [line]
                                current_message_started = True
                                in_msg = True
                                in_emm_attach = False
                                eea_list = []
                                eia_list = []
                                uea_list = []
                
                # Write final record if exists
                if in_msg and current_record["message_type"]:
                    # Process the complete message block
                    self._process_message_block(current_message_lines, current_record, eea_list, eia_list, uea_list)
                    if self._validate_and_add_record(current_record, records):
                        message_count += 1
                    else:
                        error_count += 1
                
                # Write output
                write_csv_safe(records, output_path)
                
                stats = {
                    "input_file": str(input_path),
                    "output_file": str(output_path),
                    "total_lines": line_count,
                    "messages_extracted": message_count,
                    "validation_errors": error_count,
                    "file_size_mb": file_info.get("size_mb", 0)
                }
                
                logger.info("Log parsing completed", **stats)
                return stats
                
            except Exception as e:
                logger.error("Error during log parsing", error=str(e), input_file=str(input_path))
                raise
    
    def _extract_timestamp(self, line: str) -> Optional[str]:
        """Extract timestamp using multiple patterns."""
        for pattern in self.compiled_patterns["timestamp"]:
            match = pattern.search(line)
            if match:
                timestamp = match.group(1)
                # Normalize timestamp format
                try:
                    # Try to parse and standardize format
                    if '.' in timestamp:
                        dt = datetime.strptime(timestamp, '%Y %b %d %H:%M:%S.%f')
                    else:
                        dt = datetime.strptime(timestamp, '%Y %b %d %H:%M:%S')
                    return dt.strftime('%Y %b %d %H:%M:%S.%f')[:-3]  # Keep milliseconds
                except ValueError:
                    return timestamp
        return None
    
    def _extract_message_info(self, line: str) -> Optional[Tuple[str, str]]:
        """Extract message direction and type from line."""
        # Check for state messages first
        if "LTE NAS EMM State" in line:
            return "State", "EMM State"
        elif "LTE NAS ESM Procedure State" in line:
            return "State", "ESM Procedure State"
        elif "LTE NAS ESM Bearer Context State" in line:
            return "State", "ESM Bearer Context State"
        elif "LTE NAS ESM Bearer Context Info" in line:
            return "State", "ESM Bearer Context Info"
        elif "LTE NAS EMM Forbidden TAI List" in line:
            return "State", "EMM Forbidden TAI List"
        elif "LTE NAS EMM RRC Service Request" in line:
            return "State", "EMM RRC Service Request"
        
        # Check for security protected messages
        elif "LTE NAS EMM Security Protected" in line:
            if "Incoming" in line:
                return "Incoming", "Security Protected Message"
            elif "Outgoing" in line:
                return "Outgoing", "Security Protected Message"
        elif "LTE NAS ESM Security Protected" in line:
            if "Incoming" in line:
                return "Incoming", "Security Protected Message"
            elif "Outgoing" in line:
                return "Outgoing", "Security Protected Message"
        
        # Check for standard OTA messages
        elif "message_type" in self.compiled_patterns:
            for pattern in self.compiled_patterns["message_type"]:
                match = pattern.search(line)
                if match:
                    # Standard message extraction
                    try:
                        direction = match.group(1)
                        message_type = match.group(2).strip()
                        return direction, message_type
                    except IndexError:
                        # Handle patterns with different group structures
                        if "Incoming" in line:
                            return "Incoming", "Unknown Message"
                        elif "Outgoing" in line:
                            return "Outgoing", "Unknown Message"
        
        return None
    
    def _extract_fields_from_line(self, line: str, record: Dict[str, Any], 
                                 in_emm_attach: bool, eea_list: List[str], 
                                 eia_list: List[str], uea_list: List[str]) -> None:
        """Extract all fields from a single line."""
        for field_name, patterns in self.compiled_patterns.items():
            if field_name in ["timestamp", "direction", "message_type"]:
                continue  # Already handled
            
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    if field_name in ["mcc", "mnc"]:
                        # Handle multi-group patterns for MCC/MNC
                        groups = match.groups()
                        if len(groups) >= 3:
                            record[field_name] = "".join(groups[:3])
                    elif field_name in ["mme_group_id"]:
                        # Handle MME Group ID with array format
                        groups = match.groups()
                        if len(groups) >= 2:
                            record[field_name] = f"{groups[0]},{groups[1]}"
                        else:
                            record[field_name] = match.group(1)
                    elif field_name in ["ipv4"]:
                        # Handle IPv4 with multiple groups
                        groups = match.groups()
                        if len(groups) >= 2:
                            record[field_name] = groups[1]  # Use the IP address part
                        else:
                            record[field_name] = match.group(1)
                    elif field_name in ["eea", "eia", "uea"]:
                        # Handle security capabilities
                        if field_name == "eea":
                            if match.group(3) == "1":
                                eea_list.append(match.group(1))
                        elif field_name == "eia":
                            if match.group(3) == "1":
                                eia_list.append(match.group(1))
                        elif field_name == "uea":
                            if match.group(2) == "1":
                                uea_list.append(match.group(1))
                    elif field_name == "guti":
                        record[field_name] = "yes"
                    elif field_name in ["apn_ambr_dl", "apn_ambr_ul", "pdn_type", "req_type"]:
                        # Handle fields with multiple groups (value and description)
                        groups = match.groups()
                        if len(groups) >= 2:
                            record[field_name] = f"{groups[0]} ({groups[1]})"
                        else:
                            record[field_name] = match.group(1)
                    else:
                        # Handle single group patterns
                        record[field_name] = match.group(1)
                    break
        
        # Also check for simple patterns that might be missed
        self._extract_simple_patterns(line, record)
        
        # Update security capabilities
        if eea_list:
            record["eea"] = ",".join(eea_list)
        if eia_list:
            record["eia"] = ",".join(eia_list)
        if uea_list:
            record["uea"] = ",".join(uea_list)
    
    def _extract_simple_patterns(self, line: str, record: Dict[str, Any]) -> None:
        """Extract simple patterns that might be missed by the main extraction."""
        # Bearer ID
        bearer_match = re.search(r'Bearer ID = (\d+)', line)
        if bearer_match and not record.get('bearer_id'):
            record['bearer_id'] = bearer_match.group(1)
        
        # Subscription ID
        sub_match = re.search(r'Subscription ID = (\d+)', line)
        if sub_match and not record.get('subscription_id'):
            record['subscription_id'] = sub_match.group(1)
        
        # Version
        version_match = re.search(r'Version = (\d+)', line)
        if version_match and not record.get('version'):
            record['version'] = version_match.group(1)
        
        # Transaction ID
        trans_match = re.search(r'Trans Id = (\d+)', line)
        if trans_match and not record.get('trans_id'):
            record['trans_id'] = trans_match.group(1)
        
        # EMM State
        emm_state_match = re.search(r'EMM state = (.+)', line)
        if emm_state_match and not record.get('emm_state'):
            record['emm_state'] = emm_state_match.group(1)
        
        # EMM Sub-state
        emm_sub_match = re.search(r'EMM sub-state = (.+)', line)
        if emm_sub_match and not record.get('emm_sub_state'):
            record['emm_sub_state'] = emm_sub_match.group(1)
        
        # Bearer State
        bearer_state_match = re.search(r'Bearer State = (.+)', line)
        if bearer_state_match and not record.get('bearer_state'):
            record['bearer_state'] = bearer_state_match.group(1)
        
        # Procedure State
        proc_state_match = re.search(r'Procedure State = (.+)', line)
        if proc_state_match and not record.get('procedure_state'):
            record['procedure_state'] = proc_state_match.group(1)
        
        # PTI
        pti_match = re.search(r'PTI = (\d+)', line)
        if pti_match and not record.get('pti'):
            record['pti'] = pti_match.group(1)
        
        # SDF ID
        sdf_match = re.search(r'SDF ID = (\d+)', line)
        if sdf_match and not record.get('sdf_id'):
            record['sdf_id'] = sdf_match.group(1)
        
        # Connection ID
        conn_match = re.search(r'Connection ID = (\d+)', line)
        if conn_match and not record.get('connection_id'):
            record['connection_id'] = conn_match.group(1)
        
        # RB ID
        rb_match = re.search(r'RB ID = (\d+)', line)
        if rb_match and not record.get('rb_id'):
            record['rb_id'] = rb_match.group(1)
        
        # QCI
        qci_match = re.search(r'qci = (\d+)', line)
        if qci_match and not record.get('qci'):
            record['qci'] = qci_match.group(1)
        
        # NAS Key Set ID
        nas_key_match = re.search(r'nas_key_set_id = (\d+)', line)
        if nas_key_match and not record.get('nas_key_set_id'):
            record['nas_key_set_id'] = nas_key_match.group(1)
        
        # Attach Type
        att_type_match = re.search(r'att_type = (\d+).*?\((.*?)\)', line)
        if att_type_match and not record.get('att_type'):
            record['att_type'] = f"{att_type_match.group(1)} ({att_type_match.group(2)})"
        
        # TSC
        tsc_match = re.search(r'tsc = (\d+)', line)
        if tsc_match and not record.get('tsc'):
            record['tsc'] = tsc_match.group(1)
        
        # Security algorithms
        eea_match = re.search(r'(EEA\d+(_128)?) = (\d+)', line)
        if eea_match and eea_match.group(3) == '1':
            if not record.get('eea'):
                record['eea'] = eea_match.group(1)
            else:
                record['eea'] += f",{eea_match.group(1)}"
        
        eia_match = re.search(r'(EIA\d+(_128)?) = (\d+)', line)
        if eia_match and eia_match.group(3) == '1':
            if not record.get('eia'):
                record['eia'] = eia_match.group(1)
            else:
                record['eia'] += f",{eia_match.group(1)}"
        
        uea_match = re.search(r'(UEA\d+) = (\d+)', line)
        if uea_match and uea_match.group(2) == '1':
            if not record.get('uea'):
                record['uea'] = uea_match.group(1)
            else:
                record['uea'] += f",{uea_match.group(1)}"
    
    def _validate_and_add_record(self, record: Dict[str, Any], records: List[Dict[str, Any]]) -> bool:
        """Validate record and add to list if valid."""
        if self.validators.validate_record(record):
            records.append(record.copy())
            return True
        return False
    
    def _check_multi_line_field_start(self, line: str) -> Optional[str]:
        """Check if line starts a multi-line field extraction with enhanced detection."""
        multi_line_patterns = {
            'apn': r'access_point_name',
            'guti': r'Guti valid = True',
            'pdn_addr': r'pdn_addr',
            'eps_qos': r'eps_qos',
            'ue_netwk_cap': r'ue_netwk_cap',
            'plmn_info': r'PLMN_ID:',
            'bearer_context': r'Bearer Context',
            'emm_state': r'EMM state =',
            'esm_state': r'ESM.*State',
            'message_content': r'prot_config_incl =',
            'bearer_info': r'Bearer ID =',
            'connection_info': r'Connection ID =',
            'rb_info': r'RB ID =',
            'sdf_info': r'SDF ID =',
            'pti_info': r'PTI =',
            'subscription_info': r'Subscription ID =',
            'version_info': r'Version =',
            'trans_id_info': r'Trans Id =',
            'container_info': r'container_contents\[',
            'protocol_info': r'prot_or_container',
            'protocol_len': r'prot_len =',
            'container_data': r'container'
        }
        
        for field_name, pattern in multi_line_patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                return field_name
        
        # Check for message content patterns that indicate multi-line data
        content_patterns = [
            r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\d+\s*\(0x[0-9A-Fa-f]+\)',
            r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\d+\s*\([^)]+\)',
            r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[^,\s]+',
            r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]+\)'
        ]
        
        for pattern in content_patterns:
            if re.match(pattern, line):
                field_name = re.match(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*', line)
                if field_name:
                    return 'message_content'
        
        return None
    
    def _check_multi_line_field_end(self, line: str, field_name: str) -> bool:
        """Check if line ends a multi-line field extraction."""
        end_patterns = {
            'apn': r'^\s*$',  # Empty line or closing brace
            'guti': r'^\s*$',
            'pdn_addr': r'^\s*$',
            'eps_qos': r'^\s*$',
            'ue_netwk_cap': r'^\s*$',
            'plmn_info': r'^\s*$',
            'bearer_context': r'^\s*$',
            'emm_state': r'^\s*$',
            'esm_state': r'^\s*$'
        }
        
        if field_name in end_patterns:
            return bool(re.match(end_patterns[field_name], line))
        return False
    
    def _extract_multi_line_field(self, buffer: List[str], record: Dict[str, Any], 
                                 field_name: str, eea_list: List[str], eia_list: List[str], uea_list: List[str]) -> None:
        """Extract fields from multi-line buffer with enhanced field support."""
        buffer_text = '\n'.join(buffer)
        
        if field_name == 'apn':
            self._extract_apn_from_buffer(buffer_text, record)
        elif field_name == 'guti':
            self._extract_guti_from_buffer(buffer_text, record)
        elif field_name == 'pdn_addr':
            self._extract_pdn_addr_from_buffer(buffer_text, record)
        elif field_name == 'eps_qos':
            self._extract_qos_from_buffer(buffer_text, record)
        elif field_name == 'ue_netwk_cap':
            self._extract_security_capabilities_from_buffer(buffer_text, record, eea_list, eia_list, uea_list)
        elif field_name == 'plmn_info':
            self._extract_plmn_from_buffer(buffer_text, record)
        elif field_name == 'bearer_context':
            self._extract_bearer_context_from_buffer(buffer_text, record)
        elif field_name in ['emm_state', 'esm_state']:
            self._extract_state_from_buffer(buffer_text, record, field_name)
        elif field_name == 'message_content':
            self._extract_message_content_from_buffer(buffer_text, record)
        elif field_name in ['bearer_info', 'connection_info', 'rb_info', 'sdf_info', 'pti_info', 
                           'subscription_info', 'version_info', 'trans_id_info']:
            self._extract_simple_fields_from_buffer(buffer_text, record, field_name)
        elif field_name in ['container_info', 'protocol_info', 'protocol_len', 'container_data']:
            self._extract_container_data_from_buffer(buffer_text, record)
    
    def _extract_apn_from_buffer(self, buffer_text: str, record: Dict[str, Any]) -> None:
        """Extract APN from multi-line buffer."""
        # Look for APN values in the buffer
        apn_pattern = r'acc_pt_name_val\[\d+\] = \d+ \(.+\) \((.+)\)'
        matches = re.findall(apn_pattern, buffer_text)
        if matches:
            # Convert ASCII values to characters
            apn_chars = []
            for match in matches:
                try:
                    char_code = int(match)
                    if 32 <= char_code <= 126:  # Printable ASCII
                        apn_chars.append(chr(char_code))
                except ValueError:
                    continue
            
            if apn_chars:
                record['apn'] = ''.join(apn_chars)
    
    def _extract_guti_from_buffer(self, buffer_text: str, record: Dict[str, Any]) -> None:
        """Extract GUTI information from multi-line buffer."""
        # Extract MCC
        mcc_pattern = r'MCC digit 1 = (\d+).*MCC digit 2 = (\d+).*MCC digit 3 = (\d+)'
        mcc_match = re.search(mcc_pattern, buffer_text, re.DOTALL)
        if mcc_match:
            record['mcc'] = ''.join(mcc_match.groups())
        
        # Extract MNC
        mnc_pattern = r'MNC digit 1 = (\d+).*MNC digit 2 = (\d+).*MNC digit 3 = (\d+)'
        mnc_match = re.search(mnc_pattern, buffer_text, re.DOTALL)
        if mnc_match:
            record['mnc'] = ''.join(mnc_match.groups())
        
        # Extract MME Group ID
        mme_group_pattern = r'MME Group Id = \{ (\d+), (\d+) \}'
        mme_group_match = re.search(mme_group_pattern, buffer_text)
        if mme_group_match:
            record['mme_group_id'] = f"{mme_group_match.group(1)},{mme_group_match.group(2)}"
        
        # Extract MME Code
        mme_code_pattern = r'MME Code = (\d+)'
        mme_code_match = re.search(mme_code_pattern, buffer_text)
        if mme_code_match:
            record['mme_code'] = mme_code_match.group(1)
        
        # Extract TMSI
        tmsi_pattern = r'M TMSI = (\d+) \(0x[0-9a-fA-F]+\)'
        tmsi_match = re.search(tmsi_pattern, buffer_text)
        if tmsi_match:
            record['tmsi'] = tmsi_match.group(1)
        
        # Set GUTI flag
        record['guti'] = 'yes'
    
    def _extract_pdn_addr_from_buffer(self, buffer_text: str, record: Dict[str, Any]) -> None:
        """Extract PDN address information from multi-line buffer."""
        # Extract IPv4 address
        ipv4_pattern = r'ipv4_addr = \d+ \(0x[0-9a-fA-F]+\) \(([ 0-9\.]+)\)'
        ipv4_match = re.search(ipv4_pattern, buffer_text)
        if ipv4_match:
            record['ipv4'] = ipv4_match.group(1)
        
        # Extract PDN type
        pdn_type_pattern = r'pdn_type = (\d+).*?\(([^)]+)\)'
        pdn_type_match = re.search(pdn_type_pattern, buffer_text)
        if pdn_type_match:
            record['pdn_type'] = f"{pdn_type_match.group(1)} ({pdn_type_match.group(2)})"
    
    def _extract_qos_from_buffer(self, buffer_text: str, record: Dict[str, Any]) -> None:
        """Extract QoS information from multi-line buffer."""
        # Extract QCI
        qci_pattern = r'qci = (\d+) \(0x[0-9a-fA-F]+\) \(QC\d+\)'
        qci_match = re.search(qci_pattern, buffer_text)
        if qci_match:
            record['qci'] = qci_match.group(1)
    
    def _extract_security_capabilities_from_buffer(self, buffer_text: str, record: Dict[str, Any],
                                                  eea_list: List[str], eia_list: List[str], uea_list: List[str]) -> None:
        """Extract security capabilities from multi-line buffer."""
        # Extract EEA algorithms
        eea_pattern = r'(EEA\d+(_128)?) = (\d+)'
        for match in re.finditer(eea_pattern, buffer_text):
            if match.group(3) == '1':
                eea_list.append(match.group(1))
        
        # Extract EIA algorithms
        eia_pattern = r'(EIA\d+(_128)?) = (\d+)'
        for match in re.finditer(eia_pattern, buffer_text):
            if match.group(3) == '1':
                eia_list.append(match.group(1))
        
        # Extract UEA algorithms
        uea_pattern = r'(UEA\d+) = (\d+)'
        for match in re.finditer(uea_pattern, buffer_text):
            if match.group(2) == '1':
                uea_list.append(match.group(1))
        
        # Update security capabilities
        if eea_list:
            record['eea'] = ','.join(eea_list)
        if eia_list:
            record['eia'] = ','.join(eia_list)
        if uea_list:
            record['uea'] = ','.join(uea_list)
    
    def _extract_plmn_from_buffer(self, buffer_text: str, record: Dict[str, Any]) -> None:
        """Extract PLMN information from multi-line buffer."""
        # Extract MCC
        mcc_pattern = r'MCC digit 1 = (\d+).*MCC digit 2 = (\d+).*MCC digit 3 = (\d+)'
        mcc_match = re.search(mcc_pattern, buffer_text, re.DOTALL)
        if mcc_match:
            record['mcc'] = ''.join(mcc_match.groups())
        
        # Extract MNC
        mnc_pattern = r'MNC digit 1 = (\d+).*MNC digit 2 = (\d+).*MNC digit 3 = (\d+)'
        mnc_match = re.search(mnc_pattern, buffer_text, re.DOTALL)
        if mnc_match:
            record['mnc'] = ''.join(mnc_match.groups())
    
    def _extract_bearer_context_from_buffer(self, buffer_text: str, record: Dict[str, Any]) -> None:
        """Extract bearer context information from multi-line buffer."""
        # Extract Bearer ID
        bearer_id_pattern = r'Bearer ID = (\d+)'
        bearer_id_match = re.search(bearer_id_pattern, buffer_text)
        if bearer_id_match:
            record['bearer_id'] = bearer_id_match.group(1)
        
        # Extract Bearer State
        bearer_state_pattern = r'Bearer State = (.+)'
        bearer_state_match = re.search(bearer_state_pattern, buffer_text)
        if bearer_state_match:
            record['bearer_state'] = bearer_state_match.group(1)
        
        # Extract Connection ID
        conn_id_pattern = r'Connection ID = (\d+)'
        conn_id_match = re.search(conn_id_pattern, buffer_text)
        if conn_id_match:
            record['connection_id'] = conn_id_match.group(1)
        
        # Extract RB ID
        rb_id_pattern = r'RB ID = (\d+)'
        rb_id_match = re.search(rb_id_pattern, buffer_text)
        if rb_id_match:
            record['rb_id'] = rb_id_match.group(1)
    
    def _extract_message_content_from_buffer(self, buffer_text: str, record: Dict[str, Any]) -> None:
        """Extract message content from multi-line buffer."""
        # Extract various message content fields
        content_fields = {
            'prot_config_incl': r'prot_config_incl = (\d+)',
            'ext_prot_config_incl': r'ext_prot_config_incl = (\d+)',
            'add_update_result_incl': r'add_update_result_incl = (\d+)',
            't3412_ext_incl': r't3412_ext_incl = (\d+)',
            't3324_incl': r't3324_incl = (\d+)',
            'ext_drx_par_incl': r'ext_drx_par_incl = (\d+)',
            'dcn_id_incl': r'dcn_id_incl = (\d+)',
            'sms_srvc_status_incl': r'sms_srvc_status_incl = (\d+)',
            'non_3gpp_access_emerg_num_policy_incl': r'non_3gpp_access_emerg_num_policy_incl = (\d+)',
            't3448_incl': r't3448_incl = (\d+)',
            'nwk_policy_incl': r'nwk_policy_incl = (\d+)',
            't3447_ext_incl': r't3447_ext_incl = (\d+)',
            'ext_emergency_number_incl': r'ext_emergency_number_incl = (\d+)',
            'cipher_ket_data_incl': r'cipher_ket_data_incl = (\d+)',
            'serv_plmn_rate_ctrl_incl': r'serv_plmn_rate_ctrl_incl = (\d+)',
            'ext_apn_ambr_incl': r'ext_apn_ambr_incl = (\d+)',
            'ext_eps_qos_incl': r'ext_eps_qos_incl = (\d+)'
        }
        
        for field_name, pattern in content_fields.items():
            match = re.search(pattern, buffer_text)
            if match:
                record[field_name] = match.group(1)
    
    def _extract_simple_fields_from_buffer(self, buffer_text: str, record: Dict[str, Any], field_type: str) -> None:
        """Extract simple fields from multi-line buffer."""
        field_patterns = {
            'bearer_info': r'Bearer ID = (\d+)',
            'connection_info': r'Connection ID = (\d+)',
            'rb_info': r'RB ID = (\d+)',
            'sdf_info': r'SDF ID = (\d+)',
            'pti_info': r'PTI = (\d+)',
            'subscription_info': r'Subscription ID = (\d+)',
            'version_info': r'Version = (\d+)',
            'trans_id_info': r'Trans Id = (\d+)'
        }
        
        if field_type in field_patterns:
            match = re.search(field_patterns[field_type], buffer_text)
            if match:
                field_name = field_type.replace('_info', '')
                record[field_name] = match.group(1)
    
    def _extract_container_data_from_buffer(self, buffer_text: str, record: Dict[str, Any]) -> None:
        """Extract container data from multi-line buffer."""
        # Extract protocol length
        prot_len_match = re.search(r'prot_len = (\d+)', buffer_text)
        if prot_len_match:
            record['protocol_length'] = prot_len_match.group(1)
        
        # Extract container contents
        container_matches = re.findall(r'container_contents\[(\d+)\] = (\d+)', buffer_text)
        if container_matches:
            container_data = []
            for index, value in container_matches:
                container_data.append(f"[{index}]={value}")
            record['container_contents'] = ';'.join(container_data)
        
        # Extract protocol information
        prot_info_match = re.search(r'prot_or_container', buffer_text)
        if prot_info_match:
            record['protocol_info'] = 'present'
    
    def _extract_state_from_buffer(self, buffer_text: str, record: Dict[str, Any], field_name: str) -> None:
        """Extract state information from multi-line buffer."""
        if field_name == 'emm_state':
            # Extract EMM state
            emm_state_pattern = r'EMM state = (.+)'
            emm_state_match = re.search(emm_state_pattern, buffer_text)
            if emm_state_match:
                record['emm_state'] = emm_state_match.group(1)
            
            # Extract EMM sub-state
            emm_sub_state_pattern = r'EMM sub-state = (.+)'
            emm_sub_state_match = re.search(emm_sub_state_pattern, buffer_text)
            if emm_sub_state_match:
                record['emm_sub_state'] = emm_sub_state_match.group(1)
        
        elif field_name == 'esm_state':
            # Extract ESM procedure state
            proc_state_pattern = r'Procedure State = (.+)'
            proc_state_match = re.search(proc_state_pattern, buffer_text)
            if proc_state_match:
                record['procedure_state'] = proc_state_match.group(1)
            
            # Extract PTI
            pti_pattern = r'PTI = (\d+)'
            pti_match = re.search(pti_pattern, buffer_text)
            if pti_match:
                record['pti'] = pti_match.group(1)
            
            # Extract SDF ID
            sdf_pattern = r'SDF ID = (\d+)'
            sdf_match = re.search(sdf_pattern, buffer_text)
            if sdf_match:
                record['sdf_id'] = sdf_match.group(1) 
    
    def _process_message_block(self, message_lines: List[str], record: Dict[str, Any], 
                             eea_list: List[str], eia_list: List[str], uea_list: List[str]) -> None:
        """Process a complete message block to extract all fields."""
        message_text = '\n'.join(message_lines)
        
        # Debug: Log the message being processed
        logger.debug(f"Processing message: {record.get('message_type', 'Unknown')} - {len(message_lines)} lines")
        
        # Extract fields from the complete message block
        for field_name, patterns in self.compiled_patterns.items():
            if field_name in ["timestamp", "direction", "message_type"]:
                continue  # Already handled
            
            for pattern in patterns:
                match = pattern.search(message_text)
                if match:
                    logger.debug(f"Found match for {field_name}: {match.group(1) if match.groups() else 'matched'}")
                    if field_name in ["mcc", "mnc"]:
                        # Handle multi-group patterns for MCC/MNC
                        groups = match.groups()
                        if len(groups) >= 3:
                            record[field_name] = "".join(groups[:3])
                    elif field_name in ["mme_group_id"]:
                        # Handle MME Group ID with array format
                        groups = match.groups()
                        if len(groups) >= 2:
                            # Convert to integer format
                            group_id_1 = int(groups[0])
                            group_id_2 = int(groups[1])
                            combined_id = group_id_1 * 1000 + group_id_2
                            record[field_name] = str(combined_id)
                        else:
                            record[field_name] = match.group(1)
                    elif field_name in ["ipv4"]:
                        # Handle IPv4 with multiple groups
                        groups = match.groups()
                        if len(groups) >= 2:
                            record[field_name] = groups[1]  # Use the IP address part
                        else:
                            record[field_name] = match.group(1)
                    elif field_name in ["eea", "eia", "uea"]:
                        # Handle security capabilities
                        if field_name == "eea":
                            if match.group(3) == "1":
                                eea_list.append(match.group(1))
                        elif field_name == "eia":
                            if match.group(3) == "1":
                                eia_list.append(match.group(1))
                        elif field_name == "uea":
                            if match.group(2) == "1":
                                uea_list.append(match.group(1))
                    elif field_name == "guti":
                        record[field_name] = "yes"
                    elif field_name in ["apn_ambr_dl", "apn_ambr_ul", "pdn_type", "req_type"]:
                        # Handle fields with multiple groups (value and description)
                        groups = match.groups()
                        if len(groups) >= 2:
                            # Extract just the numeric value, not the description
                            numeric_value = groups[0]
                            if numeric_value.isdigit():
                                record[field_name] = numeric_value
                            else:
                                record[field_name] = f"{groups[0]} ({groups[1]})"
                        else:
                            # Clean up format if it contains parentheses
                            value = match.group(1)
                            if '(' in value:
                                clean_match = re.search(r'(\d+)\s*\(', value)
                                if clean_match:
                                    record[field_name] = clean_match.group(1)
                                else:
                                    record[field_name] = value
                            else:
                                record[field_name] = value
                    else:
                        # Handle single group patterns
                        record[field_name] = match.group(1)
                    break
        
        # Also extract simple patterns from the complete message block
        self._extract_simple_patterns_from_block(message_text, record)
        
        # Update security capabilities
        if eea_list:
            record["eea"] = ",".join(eea_list)
        if eia_list:
            record["eia"] = ",".join(eia_list)
        if uea_list:
            record["uea"] = ",".join(uea_list)
        
        # Debug: Log extracted fields
        extracted_fields = {k: v for k, v in record.items() if v}
        if extracted_fields:
            logger.debug(f"Extracted fields: {extracted_fields}")
    
    def _extract_simple_patterns_from_block(self, message_text: str, record: Dict[str, Any]) -> None:
        """Extract simple patterns from the complete message block."""
        # Bearer ID
        bearer_match = re.search(r'Bearer ID = (\d+)', message_text)
        if bearer_match and not record.get('bearer_id'):
            record['bearer_id'] = bearer_match.group(1)
        
        # Subscription ID
        sub_match = re.search(r'Subscription ID = (\d+)', message_text)
        if sub_match and not record.get('subscription_id'):
            record['subscription_id'] = sub_match.group(1)
        
        # Version
        version_match = re.search(r'Version = (\d+)', message_text)
        if version_match and not record.get('version'):
            record['version'] = version_match.group(1)
        
        # Transaction ID
        trans_match = re.search(r'Trans Id = (\d+)', message_text)
        if trans_match and not record.get('trans_id'):
            record['trans_id'] = trans_match.group(1)
        
        # EMM State
        emm_state_match = re.search(r'EMM state = (.+)', message_text)
        if emm_state_match and not record.get('emm_state'):
            # Clean up the state value (remove extra newlines and content)
            state_value = emm_state_match.group(1).strip()
            # Extract just the state name, not the entire block
            if '\n' in state_value:
                state_value = state_value.split('\n')[0].strip()
            # Remove any extra whitespace and newlines
            state_value = re.sub(r'\s+', ' ', state_value).strip()
            record['emm_state'] = state_value
        
        # EMM Sub-state
        emm_sub_match = re.search(r'EMM sub-state = (.+)', message_text)
        if emm_sub_match and not record.get('emm_sub_state'):
            # Clean up the sub-state value
            sub_state_value = emm_sub_match.group(1).strip()
            if '\n' in sub_state_value:
                sub_state_value = sub_state_value.split('\n')[0].strip()
            # Remove any extra whitespace and newlines
            sub_state_value = re.sub(r'\s+', ' ', sub_state_value).strip()
            record['emm_sub_state'] = sub_state_value
        
        # Bearer State
        bearer_state_match = re.search(r'Bearer State = (.+)', message_text)
        if bearer_state_match and not record.get('bearer_state'):
            # Clean up the bearer state value
            bearer_state_value = bearer_state_match.group(1).strip()
            if '\n' in bearer_state_value:
                bearer_state_value = bearer_state_value.split('\n')[0].strip()
            # Remove any extra whitespace and newlines
            bearer_state_value = re.sub(r'\s+', ' ', bearer_state_value).strip()
            record['bearer_state'] = bearer_state_value
        
        # Procedure State
        proc_state_match = re.search(r'Procedure State = (.+)', message_text)
        if proc_state_match and not record.get('procedure_state'):
            # Clean up the procedure state value
            proc_state_value = proc_state_match.group(1).strip()
            if '\n' in proc_state_value:
                proc_state_value = proc_state_value.split('\n')[0].strip()
            # Remove any extra whitespace and newlines
            proc_state_value = re.sub(r'\s+', ' ', proc_state_value).strip()
            record['procedure_state'] = proc_state_value
        
        # PTI
        pti_match = re.search(r'PTI = (\d+)', message_text)
        if pti_match and not record.get('pti'):
            record['pti'] = pti_match.group(1)
        
        # SDF ID
        sdf_match = re.search(r'SDF ID = (\d+)', message_text)
        if sdf_match and not record.get('sdf_id'):
            record['sdf_id'] = sdf_match.group(1)
        
        # Connection ID
        conn_match = re.search(r'Connection ID = (\d+)', message_text)
        if conn_match and not record.get('connection_id'):
            record['connection_id'] = conn_match.group(1)
        
        # RB ID
        rb_match = re.search(r'RB ID = (\d+)', message_text)
        if rb_match and not record.get('rb_id'):
            record['rb_id'] = rb_match.group(1)
        
        # QCI
        qci_match = re.search(r'qci = (\d+)', message_text)
        if qci_match and not record.get('qci'):
            record['qci'] = qci_match.group(1)
        
        # NAS Key Set ID
        nas_key_match = re.search(r'nas_key_set_id = (\d+)', message_text)
        if nas_key_match and not record.get('nas_key_set_id'):
            record['nas_key_set_id'] = nas_key_match.group(1)
        
        # Attach Type
        att_type_match = re.search(r'att_type = (\d+).*?\((.*?)\)', message_text)
        if att_type_match and not record.get('att_type'):
            record['att_type'] = f"{att_type_match.group(1)} ({att_type_match.group(2)})"
        
        # TSC
        tsc_match = re.search(r'tsc = (\d+)', message_text)
        if tsc_match and not record.get('tsc'):
            record['tsc'] = tsc_match.group(1)
        
        # Security algorithms
        eea_matches = re.findall(r'(EEA\d+(_128)?) = (\d+)', message_text)
        for match in eea_matches:
            if match[2] == '1':
                if not record.get('eea'):
                    record['eea'] = match[0]
                else:
                    record['eea'] += f",{match[0]}"
        
        eia_matches = re.findall(r'(EIA\d+(_128)?) = (\d+)', message_text)
        for match in eia_matches:
            if match[2] == '1':
                if not record.get('eia'):
                    record['eia'] = match[0]
                else:
                    record['eia'] += f",{match[0]}"
        
        uea_matches = re.findall(r'(UEA\d+) = (\d+)', message_text)
        for match in uea_matches:
            if match[1] == '1':
                if not record.get('uea'):
                    record['uea'] = match[0]
                else:
                    record['uea'] += f",{match[0]}"
        
        # MCC/MNC from PLMN_ID section
        mcc_matches = re.findall(r'MCC digit (\d+) = (\d+)', message_text)
        if mcc_matches and not record.get('mcc'):
            mcc_digits = [''] * 3
            for digit_pos, digit_val in mcc_matches:
                mcc_digits[int(digit_pos) - 1] = digit_val
            record['mcc'] = ''.join(mcc_digits)
        
        mnc_matches = re.findall(r'MNC digit (\d+) = (\d+)', message_text)
        if mnc_matches and not record.get('mnc'):
            mnc_digits = [''] * 3
            for digit_pos, digit_val in mnc_matches:
                mnc_digits[int(digit_pos) - 1] = digit_val
            record['mnc'] = ''.join(mnc_digits)
        
        # MME Group ID - Clean up format
        mme_group_match = re.search(r'MME Group Id = \{ (\d+), (\d+) \}', message_text)
        if mme_group_match and not record.get('mme_group_id'):
            # Convert to integer format (combine the two numbers)
            group_id_1 = int(mme_group_match.group(1))
            group_id_2 = int(mme_group_match.group(2))
            # Combine as a single integer (e.g., 30,250 -> 30250)
            combined_id = group_id_1 * 1000 + group_id_2
            record['mme_group_id'] = str(combined_id)
        
        # MME Code
        mme_code_match = re.search(r'MME Code = (\d+)', message_text)
        if mme_code_match and not record.get('mme_code'):
            record['mme_code'] = mme_code_match.group(1)
        
        # TMSI - Clean up hex format
        tmsi_match = re.search(r'M TMSI = (0x[0-9a-fA-F]+)', message_text)
        if tmsi_match and not record.get('tmsi'):
            # Convert hex to decimal
            hex_value = tmsi_match.group(1)
            try:
                decimal_value = int(hex_value, 16)
                record['tmsi'] = str(decimal_value)
            except ValueError:
                record['tmsi'] = hex_value
        
        # GUTI flag
        if 'Guti valid = True' in message_text and not record.get('guti'):
            record['guti'] = 'yes'
        
        # Clean up PDN type format
        if record.get('pdn_type') and '(' in record['pdn_type']:
            # Extract just the number before the parentheses
            pdn_match = re.search(r'(\d+)\s*\(', record['pdn_type'])
            if pdn_match:
                record['pdn_type'] = pdn_match.group(1)
        
        # Clean up request type format
        if record.get('req_type') and '(' in record['req_type']:
            # Extract just the number before the parentheses
            req_match = re.search(r'(\d+)\s*\(', record['req_type'])
            if req_match:
                record['req_type'] = req_match.group(1)
        
        # Clean up APN AMBR format
        if record.get('apn_ambr_dl') and '(' in record['apn_ambr_dl']:
            # Extract just the number before the parentheses
            ambr_match = re.search(r'(\d+)\s*\(', record['apn_ambr_dl'])
            if ambr_match:
                record['apn_ambr_dl'] = ambr_match.group(1)
        
        if record.get('apn_ambr_ul') and '(' in record['apn_ambr_ul']:
            # Extract just the number before the parentheses
            ambr_match = re.search(r'(\d+)\s*\(', record['apn_ambr_ul'])
            if ambr_match:
                record['apn_ambr_ul'] = ambr_match.group(1) 