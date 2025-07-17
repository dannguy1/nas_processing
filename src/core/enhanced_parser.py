"""Enhanced NAS parser with YAML message definition integration."""

import re
import csv
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import pandas as pd
import structlog

from .message_definitions import MessageDefinitionLoader, EnhancedMessageProcessor, Technology
from .parser import NASParser
from ..utils.logger import PerformanceLogger
from ..utils.file_handler import write_csv_safe, get_file_info

logger = structlog.get_logger(__name__)


class EnhancedNASParser(NASParser):
    """Enhanced NAS Parser with YAML message definition integration."""
    
    def __init__(self, config_path: Optional[str] = None, 
                 lte_spec_path: Optional[str] = None, 
                 nr_spec_path: Optional[str] = None):
        """Initialize enhanced parser with message definitions."""
        super().__init__(config_path)
        
        # Initialize message definition components
        self.message_loader = MessageDefinitionLoader(lte_spec_path, nr_spec_path)
        self.message_processor = EnhancedMessageProcessor(self.message_loader)
        
        # Add enhanced fields to fieldnames
        self.enhanced_fields = [
            'technology', 'procedure', 'hex_code', 'description', 
            'definition_found', 'validation_errors', 'sequence_errors',
            'expected_fields', 'extracted_fields_count'
        ]
        self.fieldnames.extend(self.enhanced_fields)
        
        logger.info("Enhanced NAS Parser initialized", 
                   enhanced_fields=len(self.enhanced_fields))
    
    def parse_log(self, input_file: str, output_file: str) -> Dict[str, Any]:
        """Enhanced log parsing with YAML definition integration and container analysis."""
        logger.info("Starting enhanced NAS log parsing", input_file=input_file, output_file=output_file)
        
        # Store input file path for container analysis
        self.current_input_file = input_file
        
        # Use a temporary file for parent class parsing
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as temp_file:
            temp_output = temp_file.name
        
        try:
            # Parse with parent class to temporary file
            base_result = super().parse_log(input_file, temp_output)
            
            # Enhance the parsed data with YAML definitions
            enhanced_records = self._enhance_records_with_definitions(base_result.get('records', []))
            
            # Enhance records with container information
            container_enhanced_records = self._enhance_records_with_containers(enhanced_records)
            
            # Write consolidated enhanced results directly to the target file
            self._write_enhanced_csv(container_enhanced_records, output_file)
            
            # Generate comprehensive analysis report
            analysis_report = self._generate_analysis_report(container_enhanced_records)
            
            # Add container analysis to the report
            container_analysis = self._generate_container_analysis_report(container_enhanced_records)
            analysis_report['container_analysis'] = container_analysis
            
            # Update the result with enhanced data
            result = {
                'records': container_enhanced_records,
                'analysis_report': analysis_report,
                'base_parser_result': base_result
            }
            
            logger.info("Enhanced parsing completed", 
                       enhanced_records=len(container_enhanced_records))
            
            return result
            
        finally:
            # Clean up temporary file
            import os
            if os.path.exists(temp_output):
                os.unlink(temp_output)
    
    def _enhance_records_with_definitions(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance parsed records with YAML definition information."""
        enhanced_records = []
        
        for record in records:
            enhanced_record = record.copy()
            message_type = record.get('message_type', '')
            message_text = self._get_message_text(record)
            
            # Enhanced technology detection
            technology = self._detect_technology(record, message_type, message_text)
            enhanced_record['technology'] = technology
            
            if message_type:
                # Identify message using YAML definitions
                message_info = self.message_processor.identify_message(message_text, message_type)
                
                # Extract fields based on message definition
                extracted_fields = self.message_processor.extract_fields_for_message(message_text, message_type)
                
                # Validate message fields
                validation_errors = self.message_processor.validate_message_fields(message_text, message_type)
                
                # Add enhanced information
                enhanced_record.update({
                    'procedure': message_info.get('procedure', ''),
                    'hex_code': message_info.get('hex_code', ''),
                    'description': message_info.get('description', ''),
                    'definition_found': message_info.get('definition_found', False),
                    'validation_errors': '; '.join(validation_errors) if validation_errors else '',
                    'expected_fields': '; '.join(message_info.get('expected_fields', [])),
                    'extracted_fields_count': len(extracted_fields)
                })
                
                # Add extracted fields
                for field_name, field_value in extracted_fields.items():
                    enhanced_record[f'extracted_{field_name}'] = field_value
            
            enhanced_records.append(enhanced_record)
        
        return enhanced_records
    
    def _detect_technology(self, record: Dict[str, Any], message_type: str, message_text: str) -> str:
        """Enhanced technology detection for 5G NR and LTE."""
        # Check for explicit 5G NR indicators
        if any(indicator in message_type.upper() for indicator in ['MM5G', 'NR5G', '5G']):
            return '5G'
        
        # Check for 5G NR specific fields
        if any(field in record for field in ['amf_region_id', 'amf_set_id', 'amf_pointer', 'fiveg_tmsi', 'mm5g_state']):
            return '5G'
        
        # Check for 5G NR security algorithms
        if any(field in record for field in ['ea0_5g', 'ea1_128_5g', 'ea2_128_5g', 'ea3_128_5g', 'ia1_128_5g', 'ia2_128_5g', 'ia3_128_5g']):
            return '5G'
        
        # Check for 5G NR capabilities
        if any(field in record for field in ['fivegmm_cap_len', 'fivegc_cap', 's1_mode_cap', 'ho_attach_cap']):
            return '5G'
        
        # Check for 5G NR registration types
        if record.get('registration_type', '').upper().find('5GS') != -1:
            return '5G'
        
        # Check message text for 5G NR indicators
        if message_text and any(indicator in message_text.upper() for indicator in ['NR5G', 'MM5G', '5G_GUTI', 'AMF_Region_ID', 'AMF_SET_ID']):
            return '5G'
        
        # Check for LTE indicators
        if any(indicator in message_type.upper() for indicator in ['LTE', 'EMM', 'ESM']):
            return 'LTE'
        
        # Check for LTE specific fields
        if any(field in record for field in ['emm_state', 'emm_sub_state', 'mme_group_id', 'mme_code']):
            return 'LTE'
        
        # Default to LTE for backward compatibility
        return 'LTE'
    
    def _get_message_text(self, record: Dict[str, Any]) -> str:
        """Get message text from record for analysis by matching timestamp and message_type (case-insensitive, ignore whitespace)."""
        import re
        timestamp = record.get('timestamp', '')
        message_type = record.get('message_type', '')
        if not timestamp or not message_type:
            return ""
        
        # Normalize message_type for comparison
        def normalize(s):
            return re.sub(r'\s+', '', s).lower()
        norm_type = normalize(message_type)
        
        # Convert timestamp format from "2025 Jun 02 22:51:24.347" to match log format with flexible spacing
        ts_parts = timestamp.split()
        if len(ts_parts) >= 4:
            # Convert "02" to "2" (remove leading zero)
            day = ts_parts[2].lstrip('0')
            # Compose a regex pattern for the timestamp with fully flexible spaces
            # e.g., r"2025 Jun\s+2\s+22:51:24.347"
            log_timestamp_pattern = rf"{ts_parts[0]}\s+{ts_parts[1]}\s+{day}\s+{ts_parts[3]}"
        else:
            log_timestamp_pattern = re.escape(timestamp)
        
        block_lines = []
        found_block = False
        try:
            with open(self.current_input_file, 'r', encoding='utf-8', errors='ignore') as f:
                current_block = []
                current_ts = None
                current_type = None
                for line in f:
                    # Match the log timestamp with flexible spaces
                    ts_match = re.search(log_timestamp_pattern, line)
                    if ts_match:
                        # Extract message type from the correct position in the line
                        m = re.search(r'Message\s+--\s*(.+?)(?:\s+Msg)?$', line)
                        if m:
                            current_type = normalize(m.group(1))
                        elif 'LTE NAS ESM Procedure State' in line:
                            current_type = normalize('ESM Procedure State')
                        elif 'LTE NAS EMM State' in line:
                            current_type = normalize('EMM State')
                        elif 'LTE NAS ESM Bearer Context State' in line:
                            current_type = normalize('ESM Bearer Context State')
                        elif 'LTE NAS ESM Bearer Context Info' in line:
                            current_type = normalize('ESM Bearer Context Info')
                        elif 'LTE NAS EMM Forbidden TAI List' in line:
                            current_type = normalize('EMM Forbidden TAI List')
                        else:
                            current_type = None
                        current_ts = line.strip()[:40]
                        if found_block:
                            break
                        current_block = [line]
                        # Loosened match: normalized message type
                        if (norm_type and current_type and norm_type == current_type):
                            found_block = True
                        else:
                            found_block = False
                    else:
                        if found_block:
                            current_block.append(line)
                if found_block:
                    block_lines = current_block
        except Exception as e:
            return ""
        return "".join(block_lines)
    
    def _write_enhanced_csv(self, records: List[Dict[str, Any]], output_file: str) -> None:
        """Write enhanced records to CSV."""
        if not records:
            logger.warning("No enhanced records to write")
            # Create a minimal CSV file with headers to prevent downstream errors
            try:
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=self.fieldnames, quoting=csv.QUOTE_ALL)
                    writer.writeheader()
                logger.info(f"Created empty CSV file with headers at {output_file}")
            except Exception as e:
                logger.error(f"Failed to create empty CSV file", error=str(e))
            return
        
        try:
            # Get all unique fieldnames from all records
            all_fields = set()
            for record in records:
                all_fields.update(record.keys())
            
            # Write CSV with all fields, properly handling JSON content
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(all_fields), quoting=csv.QUOTE_ALL)
                writer.writeheader()
                
                # Process each record to handle JSON content properly
                for record in records:
                    processed_record = {}
                    for key, value in record.items():
                        if key == 'embedded_containers_json' and value:
                            # Replace newlines and ensure proper escaping for JSON content
                            if isinstance(value, str):
                                # Replace newlines with spaces to prevent CSV row breaks
                                processed_record[key] = value.replace('\n', ' ').replace('\r', ' ')
                            else:
                                processed_record[key] = str(value)
                        else:
                            processed_record[key] = value
                    
                    writer.writerow(processed_record)
            
            logger.info(f"Enhanced CSV written to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write enhanced CSV", error=str(e))
            # Fallback: write without enhanced fields
            try:
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    # Use only the original fieldnames
                    writer = csv.DictWriter(f, fieldnames=self.fieldnames, quoting=csv.QUOTE_ALL)
                    writer.writeheader()
                    # Write only the original fields
                    for record in records:
                        original_record = {k: v for k, v in record.items() if k in self.fieldnames}
                        writer.writerow(original_record)
                logger.info(f"Fallback CSV written to {output_file}")
            except Exception as e2:
                logger.error(f"Failed to write fallback CSV", error=str(e2))
    
    def _generate_analysis_report(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive analysis report with field coverage, unknown messages, and value distributions."""
        if not records:
            return {}
        
        # Technology distribution
        technology_dist = {}
        for record in records:
            tech = record.get('technology', 'Unknown')
            technology_dist[tech] = technology_dist.get(tech, 0) + 1
        
        # Procedure distribution
        procedure_dist = {}
        for record in records:
            proc = record.get('procedure', 'Unknown')
            procedure_dist[proc] = procedure_dist.get(proc, 0) + 1
        
        # Definition coverage
        definition_found = sum(1 for r in records if r.get('definition_found', False))
        definition_coverage = (definition_found / len(records)) * 100 if records else 0
        
        # Validation errors
        validation_errors = []
        for record in records:
            errors = record.get('validation_errors', '')
            if errors:
                validation_errors.append({
                    'message_type': record.get('message_type', ''),
                    'errors': errors
                })
        
        # Sequence analysis
        sequence_analysis = self._analyze_message_sequences(records)

        # --- Enhancement 1: Field Coverage Analysis ---
        from collections import defaultdict, Counter
        field_coverage = defaultdict(lambda: {'expected': 0, 'extracted': 0, 'count': 0})
        for record in records:
            msg_type = record.get('message_type', 'Unknown')
            expected_fields = set(record.get('expected_fields', '').split('; ')) if record.get('expected_fields') else set()
            extracted_fields = {k.replace('extracted_', '') for k in record if k.startswith('extracted_') and record[k]}
            field_coverage[msg_type]['expected'] += len(expected_fields)
            field_coverage[msg_type]['extracted'] += len(extracted_fields & expected_fields)
            field_coverage[msg_type]['count'] += 1
        field_coverage_report = {}
        for msg_type, stats in field_coverage.items():
            coverage = 100 * stats['extracted'] / stats['expected'] if stats['expected'] else 0
            field_coverage_report[msg_type] = {
                'coverage_percent': coverage,
                'messages_seen': stats['count'],
                'fields_expected': stats['expected'],
                'fields_extracted': stats['extracted']
            }
        
        # --- Enhancement 2: Unknown/Unused Message Detection ---
        # Messages in logs but not in YAML
        log_message_types = {r.get('message_type', '').strip() for r in records if r.get('message_type')}
        # Messages in YAML (LTE + 5G)
        yaml_message_types = set(self.message_loader.lte_by_name.keys()) | set(self.message_loader.nr_by_name.keys())
        # Lowercase for comparison
        log_message_types_lower = {m.lower() for m in log_message_types}
        unknown_in_yaml = sorted([m for m in log_message_types if m.lower() not in yaml_message_types])
        unused_in_logs = sorted([m for m in yaml_message_types if m not in log_message_types_lower])
        unknown_message_report = {
            'messages_in_logs_not_in_yaml': unknown_in_yaml,
            'messages_in_yaml_not_in_logs': unused_in_logs
        }
        
        # --- Enhancement 3: Field Value Distribution ---
        key_fields = ['emm_cause', 'attach_type', 'service_type', 'esm_cause', 'mm_cause', 'sm_cause']
        field_value_dist = {k: Counter() for k in key_fields}
        for record in records:
            for k in key_fields:
                val = record.get(f'extracted_{k}')
                if val:
                    field_value_dist[k][val] += 1
        # Convert to dicts and top-N
        field_value_dist_report = {}
        for k, counter in field_value_dist.items():
            if counter:
                field_value_dist_report[k] = counter.most_common(10)
        
        return {
            'total_messages': len(records),
            'technology_distribution': technology_dist,
            'procedure_distribution': procedure_dist,
            'definition_coverage_percent': definition_coverage,
            'validation_errors': validation_errors,
            'sequence_analysis': sequence_analysis,
            'enhanced_fields_extracted': sum(r.get('extracted_fields_count', 0) for r in records),
            'field_coverage': field_coverage_report,
            'unknown_message_report': unknown_message_report,
            'field_value_distribution': field_value_dist_report
        }
    
    def _analyze_message_sequences(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze message sequences for procedures."""
        # Group messages by procedure
        procedure_groups = {}
        for record in records:
            procedure = record.get('procedure', '')
            if procedure and procedure != 'Unknown':
                if procedure not in procedure_groups:
                    procedure_groups[procedure] = []
                procedure_groups[procedure].append(record)
        
        sequence_analysis = {}
        for procedure, messages in procedure_groups.items():
            # Sort by timestamp
            sorted_messages = sorted(messages, key=lambda x: x.get('timestamp', ''))
            
            # Validate sequence
            technology = Technology.LTE if messages[0].get('technology') == 'LTE' else Technology.NR
            sequence_errors = self.message_loader.validate_message_sequence(
                sorted_messages, procedure, technology
            )
            
            sequence_analysis[procedure] = {
                'message_count': len(messages),
                'sequence_errors': sequence_errors,
                'messages': [msg.get('message_type') for msg in sorted_messages]
            }
        
        return sequence_analysis
    
    def analyze_procedure_completion(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze procedure completion rates."""
        procedure_analysis = {}
        
        for record in records:
            procedure = record.get('procedure', '')
            if not procedure or procedure == 'Unknown':
                continue
            
            if procedure not in procedure_analysis:
                procedure_analysis[procedure] = {
                    'total_messages': 0,
                    'completed': 0,
                    'failed': 0,
                    'messages': []
                }
            
            proc_analysis = procedure_analysis[procedure]
            proc_analysis['total_messages'] += 1
            proc_analysis['messages'].append(record.get('message_type', ''))
            
            # Check for completion/failure indicators
            message_type = record.get('message_type', '').lower()
            if any(indicator in message_type for indicator in ['complete', 'accept']):
                proc_analysis['completed'] += 1
            elif any(indicator in message_type for indicator in ['reject', 'failure']):
                proc_analysis['failed'] += 1
        
        # Calculate completion rates
        for procedure, analysis in procedure_analysis.items():
            total = analysis['total_messages']
            if total > 0:
                analysis['completion_rate'] = (analysis['completed'] / total) * 100
                analysis['failure_rate'] = (analysis['failed'] / total) * 100
            else:
                analysis['completion_rate'] = 0
                analysis['failure_rate'] = 0
        
        return procedure_analysis
    
    def generate_procedure_report(self, records: List[Dict[str, Any]]) -> str:
        """Generate a detailed procedure analysis report."""
        procedure_analysis = self.analyze_procedure_completion(records)
        
        report_lines = ["=== NAS Procedure Analysis Report ===", ""]
        
        for procedure, analysis in procedure_analysis.items():
            report_lines.append(f"Procedure: {procedure}")
            report_lines.append(f"  Total Messages: {analysis['total_messages']}")
            report_lines.append(f"  Completed: {analysis['completed']}")
            report_lines.append(f"  Failed: {analysis['failed']}")
            report_lines.append(f"  Completion Rate: {analysis['completion_rate']:.1f}%")
            report_lines.append(f"  Failure Rate: {analysis['failure_rate']:.1f}%")
            report_lines.append(f"  Messages: {', '.join(analysis['messages'])}")
            report_lines.append("")
        
        return "\n".join(report_lines)
    
    def export_enhanced_analysis(self, input_file: str, output_dir: str) -> Dict[str, Any]:
        """Export comprehensive enhanced analysis."""
        # Parse with enhanced features
        result = self.parse_log(input_file, f"{output_dir}/enhanced_parsed.csv")
        
        # Generate reports
        procedure_report = self.generate_procedure_report(result['enhanced_records'])
        
        # Write reports
        report_file = f"{output_dir}/procedure_analysis.txt"
        with open(report_file, 'w') as f:
            f.write(procedure_report)
        
        # Create summary JSON
        summary = {
            'input_file': input_file,
            'output_directory': output_dir,
            'total_messages': len(result['enhanced_records']),
            'analysis_report': result['analysis_report'],
            'procedure_report_file': report_file,
            'enhanced_csv_file': result['enhanced_output']
        }
        
        # Write summary
        summary_file = f"{output_dir}/analysis_summary.json"
        import json
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info("Enhanced analysis completed", 
                   summary_file=summary_file,
                   procedure_report=report_file)
        
        return summary 

    def _extract_embedded_containers(self, message_text: str) -> Dict[str, Any]:
        """Extract embedded containers from message text with enhanced 5G NR support."""
        containers = {}
        
        if not message_text:
            return containers
        
        # Enhanced 5G NR container extraction
        containers.update(self._extract_5g_nr_containers(message_text))
        
        # Standard container extraction
        containers.update(self._extract_standard_containers(message_text))
        
        return containers
    
    def _extract_5g_nr_containers(self, message_text: str) -> Dict[str, Any]:
        """Extract 5G NR specific containers."""
        containers = {}
        
        # Extract 5G GUTI information
        guti_match = re.search(r'_5gs_mob_id.*?ident_type = (\d+).*?\(([^)]+)\)', message_text, re.DOTALL)
        if guti_match:
            containers['5g_guti_type'] = guti_match.group(1)
            containers['5g_guti_description'] = guti_match.group(2)
        
        # Extract MCC/MNC breakdown
        mcc_matches = re.findall(r'mcc_(\d+) = (\d+)', message_text)
        if mcc_matches:
            mcc_parts = [match[1] for match in sorted(mcc_matches, key=lambda x: int(x[0]))]
            containers['mcc_breakdown'] = mcc_parts
            containers['mcc_complete'] = ''.join(mcc_parts)
        
        mnc_matches = re.findall(r'mnc_(\d+) = (\d+)', message_text)
        if mnc_matches:
            mnc_parts = [match[1] for match in sorted(mnc_matches, key=lambda x: int(x[0]))]
            containers['mnc_breakdown'] = mnc_parts
            containers['mnc_complete'] = ''.join(mnc_parts)
        
        # Extract AMF information
        amf_region_match = re.search(r'AMF_Region_ID = (\d+)', message_text)
        if amf_region_match:
            containers['amf_region_id'] = amf_region_match.group(1)
        
        amf_set_match = re.search(r'AMF_SET_ID = (\d+)', message_text)
        if amf_set_match:
            containers['amf_set_id'] = amf_set_match.group(1)
        
        amf_pointer_match = re.search(r'AMF_Pointer = (\d+)', message_text)
        if amf_pointer_match:
            containers['amf_pointer'] = amf_pointer_match.group(1)
        
        # Extract 5G TMSI array
        tmsi_matches = re.findall(r'_5g_tmsi\[(\d+)\] = (\d+)', message_text)
        if tmsi_matches:
            tmsi_array = [match[1] for match in sorted(tmsi_matches, key=lambda x: int(x[0]))]
            containers['5g_tmsi_array'] = tmsi_array
            containers['5g_tmsi_hex'] = ''.join([f'{int(x):02x}' for x in tmsi_array])
        
        # Extract registration type
        reg_type_match = re.search(r'_5gs_reg_type = (\d+).*?\(([^)]+)\)', message_text)
        if reg_type_match:
            containers['registration_type_code'] = reg_type_match.group(1)
            containers['registration_type_desc'] = reg_type_match.group(2)
        
        # Extract 5G security algorithms
        ea_algorithms = []
        for i in range(8):
            ea_match = re.search(f'EA{i}_5G = (\\d+)', message_text)
            if ea_match and ea_match.group(1) == '1':
                ea_algorithms.append(f'EA{i}_5G')
        if ea_algorithms:
            containers['5g_encryption_algorithms'] = ea_algorithms
        
        ia_algorithms = []
        for i in range(8):
            ia_match = re.search(f'IA{i}_5G = (\\d+)', message_text)
            if ia_match and ia_match.group(1) == '1':
                ia_algorithms.append(f'IA{i}_5G')
        if ia_algorithms:
            containers['5g_integrity_algorithms'] = ia_algorithms
        
        # Extract 5G capabilities
        capabilities = {}
        cap_fields = ['_5GC', '_5GIPHC_CP_CIoT', 'N3_data', '_5G_CP_CIoT', 'restrictEC', 
                     'Lpp', 'HO_attach', 'S1_mode', 'RACS', 'NSSAA', '_5GLCS', 
                     'V2XCNPC5', 'V2XCEPC5', 'V2X', '_5G_UP_CIoT', '_5GSR_vcc']
        
        for field in cap_fields:
            cap_match = re.search(f'{field} = (\\d+)', message_text)
            if cap_match:
                capabilities[field] = cap_match.group(1) == '1'
        
        if capabilities:
            containers['5g_capabilities'] = capabilities
        
        # Extract NSSAI information
        nssai_match = re.search(r'num_nssai = (\d+)', message_text)
        if nssai_match:
            containers['nssai_count'] = nssai_match.group(1)
        
        sst_match = re.search(r's_nssai_val\[0\] = (\d+)', message_text)
        if sst_match:
            containers['nssai_sst'] = sst_match.group(1)
        
        # Extract TAC information
        tac_match = re.search(r'tac = (\d+)', message_text)
        if tac_match:
            containers['tac_value'] = tac_match.group(1)
        
        return containers
    
    def _extract_standard_containers(self, message_text: str) -> Dict[str, Any]:
        """Extract standard LTE containers."""
        containers = {}
        
        # Extract bearer information
        bearer_match = re.search(r'Bearer ID = (\d+)', message_text)
        if bearer_match:
            containers['bearer_id'] = bearer_match.group(1)
        
        # Extract QCI
        qci_match = re.search(r'qci = (\d+)', message_text)
        if qci_match:
            containers['qci'] = qci_match.group(1)
        
        # Extract APN
        apn_match = re.search(r'acc_pt_name_val\[(\d+)\] = \d+ \([^)]+\) \(([^)]+)\)', message_text)
        if apn_match:
            containers['apn_index'] = apn_match.group(1)
            containers['apn_name'] = apn_match.group(2)
        
        # Extract IP address
        ip_match = re.search(r'ipv4_addr = \d+ \(0x[0-9a-fA-F]+\) \(([ 0-9\.]+)\)', message_text)
        if ip_match:
            containers['ipv4_address'] = ip_match.group(1)
        
        # Extract security algorithms
        eea_algorithms = []
        for i in range(8):
            eea_match = re.search(f'EEA{i}(_128)? = (\\d+)', message_text)
            if eea_match and eea_match.group(2) == '1':
                eea_algorithms.append(f'EEA{i}')
        if eea_algorithms:
            containers['eea_algorithms'] = eea_algorithms
        
        eia_algorithms = []
        for i in range(8):
            eia_match = re.search(f'EIA{i}(_128)? = (\\d+)', message_text)
            if eia_match and eia_match.group(2) == '1':
                eia_algorithms.append(f'EIA{i}')
        if eia_algorithms:
            containers['eia_algorithms'] = eia_algorithms
        
        return containers
    
    def _analyze_container_coverage(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze embedded container coverage and statistics."""
        container_stats = {
            'total_messages': len(records),
            'messages_with_containers': 0,
            'container_types': {},
            'protocol_distribution': {},
            'dns_server_stats': {},
            'ipcp_stats': {},
            'vendor_container_stats': {}
        }
        
        for record in records:
            message_text = self._get_message_text(record)
            containers = self._extract_embedded_containers(message_text)
            
            if containers:
                container_stats['messages_with_containers'] += 1
                
                # Count container types
                for container_type in containers.keys():
                    container_stats['container_types'][container_type] = container_stats['container_types'].get(container_type, 0) + 1
                
                # Analyze protocol containers
                if 'protocol_configs' in containers:
                    for container in containers['protocol_configs']:
                        protocol_name = container['name']
                        container_stats['protocol_distribution'][protocol_name] = container_stats['protocol_distribution'].get(protocol_name, 0) + 1
                
                # Analyze DNS servers
                if 'dns_servers_ipv4' in containers:
                    ipv4_count = len(containers['dns_servers_ipv4'])
                    container_stats['dns_server_stats']['ipv4_count'] = ipv4_count
                
                if 'dns_servers_ipv6' in containers:
                    ipv6_count = len(containers['dns_servers_ipv6'])
                    container_stats['dns_server_stats']['ipv6_count'] = ipv6_count
                
                # Analyze MTU information
                if 'mtu' in containers:
                    container_stats['mtu_info'] = {
                        'mtu_value': containers['mtu']
                    }
                
                # Analyze MSISDN information
                if 'msisdn' in containers:
                    container_stats['msisdn_data'] = {
                        'msisdn_value': containers['msisdn']
                    }
                
                # Analyze APN information
                if 'apn' in containers:
                    container_stats['apn_info'] = {
                        'apn_value': containers['apn']
                    }
                
                # Analyze QCI information
                if 'qci' in containers:
                    container_stats['qci_info'] = {
                        'qci_value': containers['qci']
                    }
                
                # Analyze Bearer ID
                if 'bearer_id' in containers:
                    container_stats['bearer_id_info'] = {
                        'bearer_id_value': containers['bearer_id']
                    }
                
                # Analyze Bearer State
                if 'bearer_state' in containers:
                    container_stats['bearer_state_info'] = {
                        'bearer_state_value': containers['bearer_state']
                    }
                
                # Analyze Connection ID
                if 'connection_id' in containers:
                    container_stats['connection_id_info'] = {
                        'connection_id_value': containers['connection_id']
                    }
                
                # Analyze Vendor-specific containers
                if 'vendor_specific' in containers:
                    for vendor in containers['vendor_specific']:
                        vendor_id = vendor['id']
                        container_stats['vendor_container_stats'][vendor_id] = container_stats['vendor_container_stats'].get(vendor_id, 0) + 1
        
        # Calculate percentages
        if container_stats['total_messages'] > 0:
            container_stats['container_coverage_percentage'] = (container_stats['messages_with_containers'] / container_stats['total_messages']) * 100
        else:
            container_stats['container_coverage_percentage'] = 0
        
        return container_stats
    
    def _generate_container_analysis_report(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detailed container analysis report."""
        container_stats = self._analyze_container_coverage(records)
        
        # Extract detailed container information for reporting
        container_details = {
            'esm_containers': [],
            'protocol_containers': [],
            'dns_servers': [],
            'ipcp_configs': [],
            'mtu_info': [],
            'msisdn_data': [],
            'vendor_containers': []
        }
        
        for record in records:
            message_text = self._get_message_text(record)
            containers = self._extract_embedded_containers(message_text)
            
            if containers:
                record_info = {
                    'timestamp': record.get('timestamp', ''),
                    'message_type': record.get('message_type', ''),
                    'direction': record.get('direction', '')
                }
                
                # Add container details with record context
                if 'esm_container' in containers:
                    container_details['esm_containers'].append({**record_info, **containers['esm_container']})
                
                if 'protocol_configs' in containers:
                    for container in containers['protocol_configs']:
                        container_details['protocol_containers'].append({**record_info, **container})
                
                if 'dns_servers_ipv4' in containers:
                    container_details['dns_servers'].append({**record_info, **{'ipv4_count': len(containers['dns_servers_ipv4'])}})
                
                if 'dns_servers_ipv6' in containers:
                    container_details['dns_servers'].append({**record_info, **{'ipv6_count': len(containers['dns_servers_ipv6'])}})
                
                if 'mtu_info' in containers:
                    container_details['mtu_info'].append({**record_info, **containers['mtu_info']})
                
                if 'msisdn_data' in containers:
                    container_details['msisdn_data'].append({**record_info, **containers['msisdn_data']})
                
                if 'apn_info' in containers:
                    container_details['apn_info'] = {**record_info, **containers['apn_info']}
                
                if 'qci_info' in containers:
                    container_details['qci_info'] = {**record_info, **containers['qci_info']}
                
                if 'bearer_id_info' in containers:
                    container_details['bearer_id_info'] = {**record_info, **containers['bearer_id_info']}
                
                if 'bearer_state_info' in containers:
                    container_details['bearer_state_info'] = {**record_info, **containers['bearer_state_info']}
                
                if 'connection_id_info' in containers:
                    container_details['connection_id_info'] = {**record_info, **containers['connection_id_info']}
                
                if 'vendor_specific' in containers:
                    for vendor in containers['vendor_specific']:
                        container_details['vendor_containers'].append({**record_info, **vendor})
        
        return {
            'summary': container_stats,
            'details': container_details
        }
    
    def _enhance_records_with_containers(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance parsed records with embedded container information."""
        enhanced_records = []
        
        for record in records:
            enhanced_record = record.copy()
            message_text = self._get_message_text(record)
            containers = self._extract_embedded_containers(message_text)
            
            # Add container information to record
            if containers:
                enhanced_record['has_embedded_containers'] = True
                enhanced_record['container_types'] = list(containers.keys())
                
                # Add pretty-printed JSON container content
                import json
                enhanced_record['embedded_containers_json'] = json.dumps(containers, indent=2, ensure_ascii=False)
                
                # Add specific container data
                if 'esm_container' in containers:
                    enhanced_record['esm_container_info'] = containers['esm_container']
                
                if 'protocol_configs' in containers:
                    enhanced_record['protocol_containers_count'] = len(containers['protocol_configs'])
                    enhanced_record['protocol_container_types'] = [c['name'] for c in containers['protocol_configs']]
                
                if 'dns_servers_ipv4' in containers:
                    enhanced_record['dns_servers_ipv4_count'] = len(containers['dns_servers_ipv4'])
                
                if 'dns_servers_ipv6' in containers:
                    enhanced_record['dns_servers_ipv6_count'] = len(containers['dns_servers_ipv6'])
                
                if 'mtu' in containers:
                    enhanced_record['mtu_value'] = containers['mtu']
                
                if 'msisdn' in containers:
                    enhanced_record['msisdn_value'] = containers['msisdn']
                
                if 'apn' in containers:
                    enhanced_record['apn_value'] = containers['apn']
                
                if 'qci' in containers:
                    enhanced_record['qci_value'] = containers['qci']
                
                if 'bearer_id' in containers:
                    enhanced_record['bearer_id_value'] = containers['bearer_id']
                
                if 'bearer_state' in containers:
                    enhanced_record['bearer_state_value'] = containers['bearer_state']
                
                if 'connection_id' in containers:
                    enhanced_record['connection_id_value'] = containers['connection_id']
                
                if 'vendor_specific' in containers:
                    enhanced_record['vendor_specific_count'] = len(containers['vendor_specific'])
            else:
                enhanced_record['has_embedded_containers'] = False
                enhanced_record['embedded_containers_json'] = ""
            
            enhanced_records.append(enhanced_record)
        
        return enhanced_records 