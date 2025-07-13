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
        
        # Use parent class parsing as base
        base_result = super().parse_log(input_file, output_file)
        
        # Enhance the parsed data with YAML definitions
        enhanced_records = self._enhance_records_with_definitions(base_result.get('records', []))
        
        # Enhance records with container information
        container_enhanced_records = self._enhance_records_with_containers(enhanced_records)
        
        # Write enhanced results
        enhanced_output = output_file.replace('.csv', '_enhanced.csv').replace('.json', '_enhanced.json')
        self._write_enhanced_csv(container_enhanced_records, enhanced_output)
        
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
    
    def _enhance_records_with_definitions(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance parsed records with YAML definition information."""
        enhanced_records = []
        
        for record in records:
            enhanced_record = record.copy()
            message_type = record.get('message_type', '')
            message_text = self._get_message_text(record)
            
            if message_type:
                # Identify message using YAML definitions
                message_info = self.message_processor.identify_message(message_text, message_type)
                
                # Extract fields based on message definition
                extracted_fields = self.message_processor.extract_fields_for_message(message_text, message_type)
                
                # Validate message fields
                validation_errors = self.message_processor.validate_message_fields(message_text, message_type)
                
                # Add enhanced information
                enhanced_record.update({
                    'technology': message_info.get('technology', 'Unknown'),
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
            return
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=records[0].keys())
                writer.writeheader()
                writer.writerows(records)
            
            logger.info(f"Enhanced CSV written to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write enhanced CSV", error=str(e))
    
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
        """Extract embedded container information from message text."""
        containers = {}
        
        if not message_text:
            return containers
        
        # Extract ESM message container information - updated pattern
        esm_container_match = re.search(r'esm_msg_container\s+eps_bearer_id_or_skip_id = (\d+) \(0x[0-9a-fA-F]+\)\s+prot_disc = (\d+) \(0x[0-9a-fA-F]+\) \((.+?)\)\s+trans_id = (\d+) \(0x[0-9a-fA-F]+\)\s+msg_type = (\d+) \(0x[0-9a-fA-F]+\) \((.+?)\)', message_text, re.DOTALL)
        if esm_container_match:
            containers['esm_container'] = {
                'bearer_id': int(esm_container_match.group(1)),
                'protocol_discriminator': int(esm_container_match.group(2)),
                'protocol_name': esm_container_match.group(3),
                'transaction_id': int(esm_container_match.group(4)),
                'message_type': int(esm_container_match.group(5)),
                'message_name': esm_container_match.group(6)
            }
        
        # Extract Protocol Configuration containers
        prot_config_matches = re.findall(r'prot_or_container\[(\d+)\]\s+id = (\d+) \(0x[0-9a-fA-F]+\) \((.+?)\)', message_text)
        if prot_config_matches:
            containers['protocol_configs'] = []
            for match in prot_config_matches:
                containers['protocol_configs'].append({
                    'index': int(match[0]),
                    'id': int(match[1]),
                    'name': match[2]
                })
        
        # Extract DNS Server information
        dns_ipv4_matches = re.findall(r'DNS Server IPv4 Address.*?container_contents\[(\d+)\] = (\d+)', message_text)
        if dns_ipv4_matches:
            containers['dns_servers_ipv4'] = []
            for match in dns_ipv4_matches:
                containers['dns_servers_ipv4'].append({
                    'index': int(match[0]),
                    'value': int(match[1])
                })
        
        dns_ipv6_matches = re.findall(r'DNS Server IPv6 Address.*?addr = 0x([0-9a-fA-F]+)', message_text)
        if dns_ipv6_matches:
            containers['dns_servers_ipv6'] = []
            for match in dns_ipv6_matches:
                containers['dns_servers_ipv6'].append({
                    'address': match
                })
        
        # Extract MTU information
        mtu_match = re.search(r'MTU.*?= (\d+)', message_text)
        if mtu_match:
            containers['mtu'] = int(mtu_match.group(1))
        
        # Extract MSISDN information
        msisdn_match = re.search(r'MSISDN.*?= (.+)', message_text)
        if msisdn_match:
            containers['msisdn'] = msisdn_match.group(1)
        
        # Extract APN information
        apn_match = re.search(r'APN.*?= (.+)', message_text)
        if apn_match:
            containers['apn'] = apn_match.group(1)
        
        # Extract QoS information
        qci_match = re.search(r'qci = (\d+)', message_text)
        if qci_match:
            containers['qci'] = int(qci_match.group(1))
        
        # Extract Bearer information
        bearer_id_match = re.search(r'Bearer ID = (\d+)', message_text)
        if bearer_id_match:
            containers['bearer_id'] = int(bearer_id_match.group(1))
        
        bearer_state_match = re.search(r'Bearer State = (.+)', message_text)
        if bearer_state_match:
            containers['bearer_state'] = bearer_state_match.group(1)
        
        # Extract Connection information
        connection_id_match = re.search(r'Connection ID = (\d+)', message_text)
        if connection_id_match:
            containers['connection_id'] = int(connection_id_match.group(1))
        
        # Extract Vendor-specific containers
        vendor_matches = re.findall(r'id = (\d+) \(0x[0-9a-fA-F]+\) \(unknown\)', message_text)
        if vendor_matches:
            containers['vendor_specific'] = []
            for match in vendor_matches:
                containers['vendor_specific'].append({
                    'id': int(match)
                })
        
        # Extract Container contents
        container_contents_matches = re.findall(r'container_contents\[(\d+)\] = (\d+)', message_text)
        if container_contents_matches:
            containers['container_contents'] = []
            for match in container_contents_matches:
                containers['container_contents'].append({
                    'index': int(match[0]),
                    'value': int(match[1])
                })
        
        # Extract Protocol lengths
        prot_len_matches = re.findall(r'prot_len = (\d+)', message_text)
        if prot_len_matches:
            containers['protocol_lengths'] = [int(x) for x in prot_len_matches]
        
        # Extract Number of records
        num_recs_match = re.search(r'num_recs = (\d+)', message_text)
        if num_recs_match:
            containers['num_records'] = int(num_recs_match.group(1))
        
        # Extract Security information
        security_matches = re.findall(r'(eea|eia|uea).*?= (.+)', message_text)
        if security_matches:
            containers['security_algorithms'] = {}
            for match in security_matches:
                containers['security_algorithms'][match[0]] = match[1]
        
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
            
            enhanced_records.append(enhanced_record)
        
        return enhanced_records 