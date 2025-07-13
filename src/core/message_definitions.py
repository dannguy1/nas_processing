"""Message definition loader and processor for NAS parsing."""

import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class Technology(Enum):
    """Technology types for NAS messages."""
    LTE = "LTE"
    NR = "5G"


class MessageDefinitionLoader:
    """Loads and manages message definitions from YAML specification files."""
    
    def __init__(self, lte_spec_path: Optional[str] = None, nr_spec_path: Optional[str] = None):
        """Initialize with paths to specification files."""
        self.lte_messages = self._load_specification(lte_spec_path or "src/config/TS_24_301.yaml")
        self.nr_messages = self._load_specification(nr_spec_path or "src/config/TS_24_501.yaml")
        
        # Create lookup dictionaries for fast access
        self.lte_by_name = {msg['name'].lower(): msg for msg in self.lte_messages.get('messages', [])}
        self.lte_by_hex = {msg['hex_code']: msg for msg in self.lte_messages.get('messages', [])}
        self.nr_by_name = {msg['name'].lower(): msg for msg in self.nr_messages.get('messages', [])}
        self.nr_by_hex = {msg['hex_code']: msg for msg in self.nr_messages.get('messages', [])}
        
        logger.info("Message definition loader initialized", 
                   lte_messages=len(self.lte_by_name), 
                   nr_messages=len(self.nr_by_name))
    
    def _load_specification(self, spec_path: str) -> Dict[str, Any]:
        """Load YAML specification file."""
        try:
            with open(spec_path, 'r') as f:
                spec = yaml.safe_load(f)
            logger.info(f"Loaded specification from {spec_path}", messages=len(spec.get('messages', [])))
            return spec
        except Exception as e:
            logger.error(f"Failed to load specification {spec_path}", error=str(e))
            return {'messages': []}
    
    def get_message_by_name(self, name: str, technology: Technology = Technology.LTE) -> Optional[Dict[str, Any]]:
        """Get message definition by name."""
        if technology == Technology.LTE:
            return self.lte_by_name.get(name.lower())
        else:
            return self.nr_by_name.get(name.lower())
    
    def get_message_by_hex(self, hex_code: str, technology: Technology = Technology.LTE) -> Optional[Dict[str, Any]]:
        """Get message definition by hex code."""
        if technology == Technology.LTE:
            return self.lte_by_hex.get(hex_code)
        else:
            return self.nr_by_hex.get(hex_code)
    
    def get_messages_by_procedure(self, procedure: str, technology: Technology = Technology.LTE) -> List[Dict[str, Any]]:
        """Get all messages for a specific procedure."""
        messages = self.lte_messages.get('messages', []) if technology == Technology.LTE else self.nr_messages.get('messages', [])
        return [msg for msg in messages if msg.get('procedure') == procedure]
    
    def get_expected_sequence(self, procedure: str, technology: Technology = Technology.LTE) -> List[Dict[str, Any]]:
        """Get expected message sequence for a procedure."""
        messages = self.get_messages_by_procedure(procedure, technology)
        # Sort by typical sequence order
        sequence_order = {
            'Attach': ['Attach Request', 'Attach Accept', 'Attach Complete', 'Attach Reject'],
            'Registration': ['Registration Request', 'Registration Accept', 'Registration Complete', 'Registration Reject'],
            'Detach': ['Detach Request', 'Detach Accept'],
            'Deregistration': ['Deregistration Request UE Originating', 'Deregistration Accept UE Originating'],
            'TAU': ['Tracking Area Update Request', 'Tracking Area Update Accept', 'Tracking Area Update Complete', 'Tracking Area Update Reject'],
            'Service': ['Service Request', 'Service Reject'],
            'Authentication': ['Authentication Request', 'Authentication Response', 'Authentication Reject', 'Authentication Failure'],
            'Security': ['Security Mode Command', 'Security Mode Complete', 'Security Mode Reject'],
            'Bearer_Management': ['Activate Default EPS Bearer Context Request', 'Activate Default EPS Bearer Context Accept', 'Activate Default EPS Bearer Context Reject'],
            'PDN_Connectivity': ['PDN Connectivity Request', 'PDN Connectivity Reject'],
            'PDU_Session_Establishment': ['PDU Session Establishment Request', 'PDU Session Establishment Accept', 'PDU Session Establishment Reject']
        }
        
        if procedure in sequence_order:
            ordered_messages = []
            for expected_name in sequence_order[procedure]:
                for msg in messages:
                    if msg['name'] == expected_name:
                        ordered_messages.append(msg)
                        break
            return ordered_messages
        
        return messages
    
    def validate_message_sequence(self, messages: List[Dict[str, Any]], procedure: str, technology: Technology = Technology.LTE) -> List[str]:
        """Validate if a message sequence follows expected pattern."""
        expected_sequence = self.get_expected_sequence(procedure, technology)
        errors = []
        
        if not expected_sequence:
            return errors
        
        # Check if all expected messages are present
        expected_names = [msg['name'] for msg in expected_sequence]
        actual_names = [msg.get('message_type', '') for msg in messages]
        
        for expected_name in expected_names:
            if expected_name not in actual_names:
                errors.append(f"Missing expected message: {expected_name}")
        
        # Check sequence order (basic validation)
        for i, msg in enumerate(messages):
            if i < len(expected_sequence):
                expected_msg = expected_sequence[i]
                if msg.get('message_type') != expected_msg['name']:
                    errors.append(f"Unexpected message order: expected {expected_msg['name']}, got {msg.get('message_type')}")
        
        return errors
    
    def get_required_fields(self, message_name: str, technology: Technology = Technology.LTE) -> List[str]:
        """Get required fields for a specific message."""
        msg_def = self.get_message_by_name(message_name, technology)
        if msg_def and 'fields' in msg_def:
            return msg_def['fields']
        return []
    
    def get_message_description(self, message_name: str, technology: Technology = Technology.LTE) -> Optional[str]:
        """Get description for a specific message."""
        msg_def = self.get_message_by_name(message_name, technology)
        return msg_def.get('description') if msg_def else None


class EnhancedMessageProcessor:
    """Enhanced message processing using YAML definitions."""
    
    def __init__(self, message_loader: MessageDefinitionLoader):
        """Initialize with message definition loader."""
        self.message_loader = message_loader
        self.technology_detector = TechnologyDetector()
    
    def identify_message(self, message_text: str, message_type: str) -> Dict[str, Any]:
        """Identify message using YAML definitions and extract enhanced information."""
        # Detect technology
        technology = self.technology_detector.detect_technology(message_text, message_type)
        
        # Try to find message definition
        msg_def = self.message_loader.get_message_by_name(message_type, technology)
        
        if msg_def:
            return {
                'message_type': message_type,
                'technology': technology.value,
                'procedure': msg_def.get('procedure'),
                'direction': msg_def.get('direction'),
                'hex_code': msg_def.get('hex_code'),
                'description': msg_def.get('description'),
                'expected_fields': msg_def.get('fields', []),
                'definition_found': True
            }
        else:
            return {
                'message_type': message_type,
                'technology': technology.value,
                'definition_found': False
            }
    
    def extract_fields_for_message(self, message_text: str, message_type: str) -> Dict[str, Any]:
        """Extract fields based on message definition."""
        technology = self.technology_detector.detect_technology(message_text, message_type)
        msg_def = self.message_loader.get_message_by_name(message_type, technology)
        
        if not msg_def:
            return {}
        
        extracted_fields = {}
        expected_fields = msg_def.get('fields', [])
        
        # Extract fields based on message definition
        for field in expected_fields:
            field_value = self._extract_field_value(field, message_text)
            if field_value:
                extracted_fields[field.lower().replace(' ', '_')] = field_value
        
        return extracted_fields
    
    def _extract_field_value(self, field_name: str, message_text: str) -> Optional[str]:
        """Extract specific field value from message text."""
        field_patterns = {
            'IMSI': r'IMSI[:\s]*([0-9]+)',
            'GUTI': r'GUTI[:\s]*([0-9A-Fa-f]+)',
            'Attach Type': r'attach[_\s]*type[:\s]*(\d+)',
            'EPS NAS Security Algorithms': r'security[_\s]*algorithms[:\s]*([^,\n]+)',
            'Registration Type': r'registration[_\s]*type[:\s]*(\d+)',
            'NAS Security Algorithms': r'nas[_\s]*security[_\s]*algorithms[:\s]*([^,\n]+)',
            'EMM Cause': r'emm[_\s]*cause[:\s]*(\d+)',
            'ESM Cause': r'esm[_\s]*cause[:\s]*(\d+)',
            'MM Cause': r'mm[_\s]*cause[:\s]*(\d+)',
            'SM Cause': r'sm[_\s]*cause[:\s]*(\d+)',
            'EPS Bearer ID': r'bearer[_\s]*id[:\s]*(\d+)',
            'PDU Session ID': r'pdu[_\s]*session[_\s]*id[:\s]*(\d+)',
            'QoS': r'qos[:\s]*([^,\n]+)',
            'APN': r'apn[:\s]*([^,\n]+)',
            'DNN': r'dnn[:\s]*([^,\n]+)',
            'S-NSSAI': r's[_\s]*nssai[:\s]*([^,\n]+)',
            'SSC Mode': r'ssc[_\s]*mode[:\s]*(\d+)',
            'GUAMI': r'guami[:\s]*([^,\n]+)',
            'TAI List': r'tai[_\s]*list[:\s]*([^,\n]+)',
            'Registration Result': r'registration[_\s]*result[:\s]*([^,\n]+)',
            'EPS Attach Result': r'eps[_\s]*attach[_\s]*result[:\s]*([^,\n]+)',
            'Detach Type': r'detach[_\s]*type[:\s]*(\d+)',
            'NAS Key Set Identifier': r'nas[_\s]*key[_\s]*set[_\s]*identifier[:\s]*(\d+)',
            'Service Type': r'service[_\s]*type[:\s]*(\d+)',
            'Update Type': r'update[_\s]*type[:\s]*(\d+)',
            'RAND': r'rand[:\s]*([0-9A-Fa-f]+)',
            'AUTN': r'autn[:\s]*([0-9A-Fa-f]+)',
            'RES': r'res[:\s]*([0-9A-Fa-f]+)',
            'Security Header': r'security[_\s]*header[:\s]*([^,\n]+)',
            'NAS Message': r'nas[_\s]*message[:\s]*([^,\n]+)',
            'NAS Message Container': r'nas[_\s]*message[_\s]*container[:\s]*([^,\n]+)',
            'CSFB Response': r'csfb[_\s]*response[:\s]*([^,\n]+)',
            'UE Network Capability': r'ue[_\s]*network[_\s]*capability[:\s]*([^,\n]+)',
            'PLMN List': r'plmn[_\s]*list[:\s]*([^,\n]+)',
            'Emergency Number List': r'emergency[_\s]*number[_\s]*list[:\s]*([^,\n]+)'
        }
        
        if field_name in field_patterns:
            import re
            match = re.search(field_patterns[field_name], message_text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def validate_message_fields(self, message_text: str, message_type: str) -> List[str]:
        """Validate that required fields are present in message."""
        technology = self.technology_detector.detect_technology(message_text, message_type)
        msg_def = self.message_loader.get_message_by_name(message_type, technology)
        
        if not msg_def:
            return []
        
        errors = []
        expected_fields = msg_def.get('fields', [])
        
        for field in expected_fields:
            field_value = self._extract_field_value(field, message_text)
            if not field_value:
                errors.append(f"Missing required field: {field}")
        
        return errors


class TechnologyDetector:
    """Detect technology (LTE vs 5G) from message content."""
    
    def detect_technology(self, message_text: str, message_type: str) -> Technology:
        """Detect technology based on message content and type."""
        # 5G specific indicators
        nr_indicators = [
            '5G', 'NR', '5GS', '5GMM', '5GSM', 'PDU Session', 'GUAMI', 'SUCI', 'DNN', 'S-NSSAI',
            'Registration', 'Deregistration', '5GMM', '5GSM'
        ]
        
        # LTE specific indicators
        lte_indicators = [
            'LTE', 'EPS', 'EMM', 'ESM', 'GUTI', 'IMSI', 'Attach', 'Detach', 'TAU', 'Tracking Area',
            'EPS Bearer', 'PDN', 'MME'
        ]
        
        # Check message type for technology indicators
        message_lower = message_type.lower()
        text_lower = message_text.lower()
        
        # Count technology indicators
        nr_count = sum(1 for indicator in nr_indicators if indicator.lower() in message_lower or indicator.lower() in text_lower)
        lte_count = sum(1 for indicator in lte_indicators if indicator.lower() in message_lower or indicator.lower() in text_lower)
        
        # Determine technology based on indicators
        if nr_count > lte_count:
            return Technology.NR
        else:
            return Technology.LTE 