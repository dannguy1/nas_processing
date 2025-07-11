"""
Advanced Analytics Module for NAS Log Processing System

This module provides advanced analysis capabilities including:
- Message flow analysis and correlation
- APN name decoding
- Performance metrics calculation
- Enhanced output formatting
"""

import pandas as pd
import numpy as np
import re
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timedelta
import json
import logging
import os
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import warnings

logger = logging.getLogger(__name__)


class MessageFlowAnalyzer:
    """Analyzes message flows and correlations in NAS logs"""
    
    def __init__(self):
        self.correlation_patterns = {
            'attach_flow': ['Attach request', 'Attach accept', 'Attach complete'],
            'bearer_flow': ['Activate default EPS bearer context request', 'Activate default EPS bearer context accept'],
            'security_flow': ['Security mode command', 'Security mode complete'],
            'detach_flow': ['Detach request', 'Detach accept']
        }
    
    def correlate_messages(self, messages: pd.DataFrame) -> pd.DataFrame:
        """
        Correlate related messages by transaction ID, bearer ID, and timing
        
        Args:
            messages: DataFrame with parsed NAS messages
            
        Returns:
            DataFrame with correlation information added
        """
        logger.info("Starting message correlation analysis")
        
        # Add correlation fields
        messages = messages.copy()
        messages['correlation_id'] = None
        messages['flow_type'] = None
        messages['sequence_number'] = None
        
        # Group by potential correlation keys
        correlation_groups = self._group_by_correlation_keys(messages)
        
        # Analyze each group for message flows
        for group_key, group_data in correlation_groups.items():
            flow_info = self._analyze_message_flow(group_data)
            if flow_info:
                # Update messages with correlation info
                for idx in group_data.index:
                    messages.loc[idx, 'correlation_id'] = flow_info['correlation_id']
                    messages.loc[idx, 'flow_type'] = flow_info['flow_type']
                    messages.loc[idx, 'sequence_number'] = flow_info['sequence_map'].get(idx, 0)
        
        logger.info(f"Correlation analysis complete. Found {len(messages[messages['correlation_id'].notna()])} correlated messages")
        return messages
    
    def _group_by_correlation_keys(self, messages: pd.DataFrame) -> Dict[str, pd.DataFrame]:
        """Group messages by potential correlation keys"""
        groups = {}
        
        # Group by bearer ID if available
        bearer_groups = messages[messages['bearer_id'].notna()].groupby('bearer_id')
        for bearer_id, group in bearer_groups:
            groups[f'bearer_{bearer_id}'] = group
        
        # Group by time proximity (within 30 seconds)
        time_groups = self._group_by_time_proximity(messages, window_seconds=30)
        groups.update(time_groups)
        
        # Group by message type patterns
        type_groups = self._group_by_message_patterns(messages)
        groups.update(type_groups)
        
        return groups
    
    def _group_by_time_proximity(self, messages: pd.DataFrame, window_seconds: int = 30) -> Dict[str, pd.DataFrame]:
        """Group messages by time proximity"""
        groups = {}
        messages_sorted = messages.sort_values('timestamp')
        
        current_group = []
        group_id = 0
        
        for idx, row in messages_sorted.iterrows():
            if not current_group:
                current_group.append((idx, row))
            else:
                last_time = current_group[-1][1]['timestamp']
                current_time = row['timestamp']
                
                if isinstance(last_time, str):
                    last_time = pd.to_datetime(last_time)
                if isinstance(current_time, str):
                    current_time = pd.to_datetime(current_time)
                
                time_diff = (current_time - last_time).total_seconds()
                
                if time_diff <= window_seconds:
                    current_group.append((idx, row))
                else:
                    if len(current_group) > 1:
                        group_data = pd.DataFrame([row for _, row in current_group])
                        groups[f'time_group_{group_id}'] = group_data
                        group_id += 1
                    current_group = [(idx, row)]
        
        # Handle last group
        if len(current_group) > 1:
            group_data = pd.DataFrame([row for _, row in current_group])
            groups[f'time_group_{group_id}'] = group_data
        
        return groups
    
    def _group_by_message_patterns(self, messages: pd.DataFrame) -> Dict[str, pd.DataFrame]:
        """Group messages by known flow patterns"""
        groups = {}
        
        for flow_name, pattern in self.correlation_patterns.items():
            matching_messages = messages[messages['message_type'].isin(pattern)]
            if len(matching_messages) > 0:
                groups[f'pattern_{flow_name}'] = matching_messages
        
        return groups
    
    def _analyze_message_flow(self, group_data: pd.DataFrame) -> Optional[Dict]:
        """Analyze a group of messages to identify flow patterns"""
        if len(group_data) < 2:
            return None
        
        # Sort by timestamp
        group_sorted = group_data.sort_values('timestamp')
        
        # Check for known flow patterns
        message_types = group_sorted['message_type'].tolist()
        
        for flow_name, pattern in self.correlation_patterns.items():
            if self._matches_flow_pattern(message_types, pattern):
                sequence_map = {}
                for i, (idx, row) in enumerate(group_sorted.iterrows()):
                    sequence_map[idx] = i + 1
                
                # Handle timestamp conversion
                timestamp = group_sorted.iloc[0]['timestamp']
                if isinstance(timestamp, str):
                    timestamp = pd.to_datetime(timestamp)
                timestamp_str = timestamp.strftime('%Y%m%d_%H%M%S')
                
                return {
                    'correlation_id': f"{flow_name}_{timestamp_str}",
                    'flow_type': flow_name,
                    'sequence_map': sequence_map
                }
        
        return None
    
    def _matches_flow_pattern(self, message_types: List[str], pattern: List[str]) -> bool:
        """Check if message types match a known flow pattern"""
        # Simple pattern matching - can be enhanced with more sophisticated algorithms
        pattern_set = set(pattern)
        message_set = set(message_types)
        
        # Check if we have at least 2 matching message types
        return len(pattern_set.intersection(message_set)) >= 2


class APNDecoder:
    """Decodes APN names from ASCII values in NAS logs"""
    
    def __init__(self):
        self.ascii_patterns = [
            r'APN\s*=\s*\[([\d\s,]+)\]',  # APN = [72, 101, 108, 108, 111]
            r'APN\s*=\s*([\d\s,]+)',      # APN = 72 101 108 108 111
            r'APN\s*=\s*"([^"]+)"',       # APN = "Hello"
        ]
    
    def decode_apn(self, ascii_values: List[str]) -> str:
        """
        Convert ASCII values to readable APN name
        
        Args:
            ascii_values: List of ASCII values as strings
            
        Returns:
            Decoded APN name string
        """
        try:
            apn_chars = []
            for value in ascii_values:
                # Clean the value and convert to int
                clean_value = value.strip()
                if clean_value.isdigit():
                    ascii_code = int(clean_value)
                    if 32 <= ascii_code <= 126:  # Printable ASCII
                        apn_chars.append(chr(ascii_code))
            
            return ''.join(apn_chars)
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to decode APN values {ascii_values}: {e}")
            return ''
    
    def extract_apn_from_log(self, message_text: str) -> str:
        """
        Extract and decode APN from log message text
        
        Args:
            message_text: Raw log message text
            
        Returns:
            Decoded APN name or empty string
        """
        for pattern in self.ascii_patterns:
            match = re.search(pattern, message_text)
            if match:
                if pattern.endswith('"([^"]+)"'):
                    # Already a string, return as-is
                    return match.group(1)
                else:
                    # Extract ASCII values
                    ascii_str = match.group(1)
                    ascii_values = re.findall(r'\d+', ascii_str)
                    return self.decode_apn(ascii_values)
        
        return ''
    
    def enhance_messages_with_apn(self, messages: pd.DataFrame) -> pd.DataFrame:
        """
        Enhance messages DataFrame with decoded APN names
        
        Args:
            messages: DataFrame with parsed NAS messages
            
        Returns:
            DataFrame with decoded APN names added
        """
        logger.info("Starting APN decoding for messages")
        
        messages = messages.copy()
        messages['decoded_apn'] = ''
        
        # Process messages that might contain APN information
        # Handle missing message_text column gracefully
        message_text_filter = pd.Series([False] * len(messages))
        if 'message_text' in messages.columns:
            message_text_filter = messages['message_text'].str.contains('APN', case=False, na=False)
        
        apn_candidates = messages[
            message_text_filter |
            (messages['apn'].notna())
        ]
        
        for idx, row in apn_candidates.iterrows():
            # Try to decode from message text first (if column exists)
            if 'message_text' in messages.columns and pd.notna(row['message_text']):
                decoded_apn = self.extract_apn_from_log(row['message_text'])
                if decoded_apn:
                    messages.loc[idx, 'decoded_apn'] = decoded_apn
                    continue
            
            # Try to decode from existing APN field
            if pd.notna(row['apn']):
                # Check if it's already decoded
                if not row['apn'].startswith('[') and not row['apn'].startswith('"'):
                    messages.loc[idx, 'decoded_apn'] = row['apn']
                else:
                    # Try to decode ASCII values
                    ascii_values = re.findall(r'\d+', str(row['apn']))
                    if ascii_values:
                        decoded_apn = self.decode_apn(ascii_values)
                        if decoded_apn:
                            messages.loc[idx, 'decoded_apn'] = decoded_apn
        
        decoded_count = len(messages[messages['decoded_apn'] != ''])
        logger.info(f"APN decoding complete. Decoded {decoded_count} APN names")
        
        return messages


class PerformanceAnalyzer:
    """Calculates and analyzes performance metrics from NAS messages"""
    
    def __init__(self):
        self.request_response_pairs = {
            'Attach request': 'Attach accept',
            'Activate default EPS bearer context request': 'Activate default EPS bearer context accept',
            'Security mode command': 'Security mode complete',
            'Detach request': 'Detach accept'
        }
    
    def calculate_metrics(self, messages: pd.DataFrame) -> Dict[str, Any]:
        """
        Calculate comprehensive performance metrics
        
        Args:
            messages: DataFrame with parsed NAS messages
            
        Returns:
            Dictionary containing performance metrics
        """
        logger.info("Starting performance metrics calculation")
        
        metrics = {
            'response_times': self._calculate_response_times(messages),
            'success_rates': self._calculate_success_rates(messages),
            'error_analysis': self._analyze_errors(messages),
            'message_distribution': self._analyze_message_distribution(messages),
            'timing_statistics': self._calculate_timing_statistics(messages)
        }
        
        logger.info("Performance metrics calculation complete")
        return metrics
    
    def _calculate_response_times(self, messages: pd.DataFrame) -> Dict[str, List[float]]:
        """Calculate response times between request/response pairs"""
        response_times = {}
        
        # Ensure timestamp column exists and is properly formatted
        if 'timestamp' not in messages.columns:
            logger.warning("Timestamp column not found, skipping response time calculation")
            return response_times
        
        for request_type, response_type in self.request_response_pairs.items():
            request_messages = messages[messages['message_type'] == request_type]
            response_messages = messages[messages['message_type'] == response_type]
            
            times = []
            for _, request in request_messages.iterrows():
                # Find corresponding response within reasonable time window
                request_time = pd.to_datetime(request['timestamp'])
                
                # Look for response within 60 seconds
                potential_responses = response_messages[
                    (pd.to_datetime(response_messages['timestamp']) > request_time) &
                    (pd.to_datetime(response_messages['timestamp']) <= request_time + timedelta(seconds=60))
                ]
                
                if len(potential_responses) > 0:
                    # Take the first response
                    response = potential_responses.iloc[0]
                    response_time = pd.to_datetime(response['timestamp'])
                    response_delay = (response_time - request_time).total_seconds()
                    times.append(response_delay)
            
            if times:
                response_times[f"{request_type} -> {response_type}"] = times
        
        return response_times
    
    def _calculate_success_rates(self, messages: pd.DataFrame) -> Dict[str, float]:
        """Calculate success rates for different message types"""
        success_rates = {}
        
        for request_type, response_type in self.request_response_pairs.items():
            request_count = len(messages[messages['message_type'] == request_type])
            response_count = len(messages[messages['message_type'] == response_type])
            
            if request_count > 0:
                success_rate = (response_count / request_count) * 100
                success_rates[f"{request_type}"] = success_rate
        
        return success_rates
    
    def _analyze_errors(self, messages: pd.DataFrame) -> Dict[str, Any]:
        """Analyze error patterns and statistics"""
        error_analysis = {
            'error_messages': [],
            'error_types': {},
            'error_frequency': {}
        }
        
        # Look for error indicators in message types
        error_indicators = ['reject', 'failure', 'error', 'timeout']
        
        for _, message in messages.iterrows():
            message_type = str(message['message_type']).lower()
            if any(indicator in message_type for indicator in error_indicators):
                error_analysis['error_messages'].append({
                    'timestamp': message['timestamp'],
                    'message_type': message['message_type'],
                    'message_text': message.get('message_text', '')
                })
                
                # Categorize error type
                if 'reject' in message_type:
                    error_type = 'rejection'
                elif 'failure' in message_type:
                    error_type = 'failure'
                elif 'timeout' in message_type:
                    error_type = 'timeout'
                else:
                    error_type = 'other'
                
                error_analysis['error_types'][error_type] = error_analysis['error_types'].get(error_type, 0) + 1
        
        # Calculate error frequency
        total_messages = len(messages)
        if total_messages > 0:
            error_analysis['error_frequency'] = {
                'total_errors': len(error_analysis['error_messages']),
                'error_rate': (len(error_analysis['error_messages']) / total_messages) * 100
            }
        
        return error_analysis
    
    def _analyze_message_distribution(self, messages: pd.DataFrame) -> Dict[str, int]:
        """Analyze distribution of message types"""
        return messages['message_type'].value_counts().to_dict()
    
    def _calculate_timing_statistics(self, messages: pd.DataFrame) -> Dict[str, float]:
        """Calculate timing statistics for the entire session"""
        if len(messages) < 2:
            return {}
        
        # Ensure timestamp column exists
        if 'timestamp' not in messages.columns:
            logger.warning("Timestamp column not found, skipping timing statistics")
            return {}
        
        # Convert timestamps to datetime
        timestamps = pd.to_datetime(messages['timestamp'])
        
        # Calculate session duration
        session_start = timestamps.min()
        session_end = timestamps.max()
        session_duration = (session_end - session_start).total_seconds()
        
        # Calculate message frequency
        message_frequency = len(messages) / session_duration if session_duration > 0 else 0
        
        # Calculate average time between messages
        time_diffs = timestamps.diff().dropna()
        avg_time_between_messages = time_diffs.mean().total_seconds()
        
        return {
            'session_duration_seconds': session_duration,
            'message_frequency_per_second': message_frequency,
            'avg_time_between_messages_seconds': avg_time_between_messages,
            'total_messages': len(messages)
        }


class FailurePatternDetector:
    """Detects and analyzes failure patterns in NAS message flows"""
    
    def __init__(self):
        self.failure_patterns = {
            'reject_patterns': [
                'reject', 'failure', 'error', 'timeout', 'abort'
            ],
            'common_failures': {
                'attach_reject': ['Attach reject'],
                'detach_reject': ['Detach reject'],
                'security_failure': ['Security mode reject'],
                'bearer_failure': ['Activate default EPS bearer context reject'],
                'timeout': ['timeout', 'expired'],
                'abort': ['abort', 'cancel']
            },
            'error_codes': {
                'network_reject': ['#10', '#11', '#12'],  # Network reject codes
                'security_reject': ['#20', '#21', '#22'],  # Security reject codes
                'bearer_reject': ['#30', '#31', '#32']     # Bearer reject codes
            }
        }
    
    def detect_failures(self, messages: pd.DataFrame) -> Dict[str, Any]:
        """
        Detect failure patterns in NAS messages
        
        Args:
            messages: DataFrame with parsed NAS messages
            
        Returns:
            Dictionary containing failure analysis results
        """
        logger.info("Starting failure pattern detection")
        
        failure_analysis = {
            'failure_messages': [],
            'failure_types': {},
            'failure_summary': {},
            'problematic_sessions': [],
            'recommendations': []
        }
        
        # Detect failure messages
        for idx, row in messages.iterrows():
            message_type = str(row.get('message_type', '')).lower()
            message_text = str(row.get('message_text', '')).lower()
            
            # Check for failure indicators
            is_failure = False
            failure_type = 'unknown'
            
            # Check message type patterns
            for pattern_type, patterns in self.failure_patterns['common_failures'].items():
                if any(pattern.lower() in message_type for pattern in patterns):
                    is_failure = True
                    failure_type = pattern_type
                    break
            
            # Check for general failure keywords
            if not is_failure:
                for keyword in self.failure_patterns['reject_patterns']:
                    if keyword in message_type or keyword in message_text:
                        is_failure = True
                        failure_type = 'general_failure'
                        break
            
            if is_failure:
                failure_info = {
                    'timestamp': row.get('timestamp'),
                    'message_type': row.get('message_type'),
                    'direction': row.get('direction'),
                    'failure_type': failure_type,
                    'correlation_id': row.get('correlation_id'),
                    'message_text': row.get('message_text', '')
                }
                failure_analysis['failure_messages'].append(failure_info)
                
                # Count failure types
                failure_analysis['failure_types'][failure_type] = failure_analysis['failure_types'].get(failure_type, 0) + 1
        
        # Analyze problematic sessions
        if 'correlation_id' in messages.columns:
            failure_sessions = self._analyze_failure_sessions(messages, failure_analysis['failure_messages'])
            failure_analysis['problematic_sessions'] = failure_sessions
        
        # Generate failure summary
        failure_analysis['failure_summary'] = {
            'total_failures': len(failure_analysis['failure_messages']),
            'failure_rate': (len(failure_analysis['failure_messages']) / len(messages)) * 100 if len(messages) > 0 else 0,
            'failure_types': failure_analysis['failure_types'],
            'most_common_failure': max(failure_analysis['failure_types'].items(), key=lambda x: x[1])[0] if failure_analysis['failure_types'] else 'none'
        }
        
        # Generate recommendations
        failure_analysis['recommendations'] = self._generate_recommendations(failure_analysis)
        
        logger.info(f"Failure detection complete. Found {len(failure_analysis['failure_messages'])} failure messages")
        return failure_analysis
    
    def _analyze_failure_sessions(self, messages: pd.DataFrame, failure_messages: List[Dict]) -> List[Dict]:
        """Analyze sessions that contain failures"""
        problematic_sessions = []
        
        # Group messages by correlation ID
        if 'correlation_id' in messages.columns:
            session_groups = messages[messages['correlation_id'].notna()].groupby('correlation_id')
            
            for session_id, session_messages in session_groups:
                session_failures = [f for f in failure_messages if f.get('correlation_id') == session_id]
                
                if session_failures:
                    session_info = {
                        'session_id': session_id,
                        'total_messages': len(session_messages),
                        'failure_count': len(session_failures),
                        'failure_types': list(set(f['failure_type'] for f in session_failures)),
                        'session_duration': self._calculate_session_duration(session_messages),
                        'failure_details': session_failures
                    }
                    problematic_sessions.append(session_info)
        
        return problematic_sessions
    
    def _calculate_session_duration(self, session_messages: pd.DataFrame) -> float:
        """Calculate duration of a session in seconds"""
        if len(session_messages) < 2:
            return 0.0
        
        timestamps = pd.to_datetime(session_messages['timestamp'])
        duration = (timestamps.max() - timestamps.min()).total_seconds()
        return duration
    
    def _generate_recommendations(self, failure_analysis: Dict) -> List[str]:
        """Generate recommendations based on failure patterns"""
        recommendations = []
        
        total_failures = failure_analysis['failure_summary']['total_failures']
        failure_rate = failure_analysis['failure_summary']['failure_rate']
        
        if failure_rate > 10:
            recommendations.append("High failure rate detected. Review network configuration and UE behavior.")
        
        failure_types = failure_analysis['failure_types']
        
        if 'attach_reject' in failure_types and failure_types['attach_reject'] > 0:
            recommendations.append("Attach rejections detected. Check UE credentials and network access policies.")
        
        if 'security_failure' in failure_types and failure_types['security_failure'] > 0:
            recommendations.append("Security mode failures detected. Verify encryption algorithms and security parameters.")
        
        if 'bearer_failure' in failure_types and failure_types['bearer_failure'] > 0:
            recommendations.append("Bearer activation failures detected. Review QoS settings and APN configuration.")
        
        if 'timeout' in failure_types and failure_types['timeout'] > 0:
            recommendations.append("Timeout errors detected. Check network latency and timeout configurations.")
        
        if not recommendations:
            recommendations.append("No significant failure patterns detected. System appears to be operating normally.")
        
        return recommendations


class EnhancedPerformanceAnalyzer(PerformanceAnalyzer):
    """Enhanced performance analyzer with additional metrics and visualizations"""
    
    def __init__(self):
        super().__init__()
        self.failure_detector = FailurePatternDetector()
    
    def calculate_comprehensive_metrics(self, messages: pd.DataFrame) -> Dict[str, Any]:
        """
        Calculate comprehensive performance and failure metrics
        
        Args:
            messages: DataFrame with parsed NAS messages
            
        Returns:
            Dictionary containing comprehensive analysis results
        """
        # Get basic performance metrics
        basic_metrics = self.calculate_metrics(messages)
        
        # Add failure analysis
        failure_analysis = self.failure_detector.detect_failures(messages)
        
        # Add session analysis
        session_analysis = self._analyze_sessions(messages)
        
        # Combine all metrics
        comprehensive_metrics = {
            'performance': basic_metrics,
            'failures': failure_analysis,
            'sessions': session_analysis,
            'summary': self._generate_summary(messages, basic_metrics, failure_analysis, session_analysis)
        }
        
        return comprehensive_metrics
    
    def _analyze_sessions(self, messages: pd.DataFrame) -> Dict[str, Any]:
        """Analyze session-level metrics"""
        session_analysis = {
            'total_sessions': 0,
            'session_durations': [],
            'messages_per_session': [],
            'session_types': {}
        }
        
        if 'correlation_id' in messages.columns:
            session_groups = messages[messages['correlation_id'].notna()].groupby('correlation_id')
            session_analysis['total_sessions'] = len(session_groups)
            
            for session_id, session_messages in session_groups:
                # Calculate session duration
                if len(session_messages) > 1:
                    timestamps = pd.to_datetime(session_messages['timestamp'])
                    duration = (timestamps.max() - timestamps.min()).total_seconds()
                    session_analysis['session_durations'].append(duration)
                
                # Count messages per session
                session_analysis['messages_per_session'].append(len(session_messages))
                
                # Analyze session types
                message_types = session_messages['message_type'].unique()
                session_type = self._classify_session_type(message_types)
                session_analysis['session_types'][session_type] = session_analysis['session_types'].get(session_type, 0) + 1
        
        return session_analysis
    
    def _classify_session_type(self, message_types: List[str]) -> str:
        """Classify session type based on message types"""
        message_types_lower = [mt.lower() for mt in message_types]
        
        if any('attach' in mt for mt in message_types_lower):
            return 'attach_session'
        elif any('detach' in mt for mt in message_types_lower):
            return 'detach_session'
        elif any('security' in mt for mt in message_types_lower):
            return 'security_session'
        elif any('bearer' in mt for mt in message_types_lower):
            return 'bearer_session'
        else:
            return 'other_session'
    
    def _generate_summary(self, messages: pd.DataFrame, performance: Dict, failures: Dict, sessions: Dict) -> Dict[str, Any]:
        """Generate overall summary of the analysis"""
        total_messages = len(messages)
        failure_rate = failures['failure_summary']['failure_rate']
        
        # Determine overall health score (0-100)
        health_score = max(0, 100 - failure_rate)
        
        # Determine severity level
        if failure_rate > 20:
            severity = 'critical'
        elif failure_rate > 10:
            severity = 'warning'
        elif failure_rate > 5:
            severity = 'notice'
        else:
            severity = 'normal'
        
        summary = {
            'total_messages': total_messages,
            'health_score': health_score,
            'severity_level': severity,
            'failure_rate': failure_rate,
            'total_sessions': sessions['total_sessions'],
            'avg_session_duration': np.mean(sessions['session_durations']) if sessions['session_durations'] else 0,
            'avg_messages_per_session': np.mean(sessions['messages_per_session']) if sessions['messages_per_session'] else 0,
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        return summary


class OutputFormatter:
    """Provides multiple output formats for analysis results"""
    
    def __init__(self):
        self.formatters = {
            'csv': self._format_csv,
            'json': self._format_json,
            'excel': self._format_excel,
            'html': self._format_html
        }
    
    def format_output(self, data: pd.DataFrame, format_type: str, output_path: str, 
                     additional_data: Optional[Dict] = None, input_file: str = None) -> str:
        """
        Format data to specified output format
        
        Args:
            data: DataFrame to format
            format_type: Output format ('csv', 'json', 'excel', 'html')
            output_path: Path to save the output file
            additional_data: Additional data to include (metrics, etc.)
            input_file: Path to the original input file
            
        Returns:
            Path to the generated output file
        """
        if format_type not in self.formatters:
            raise ValueError(f"Unsupported format type: {format_type}")
        
        if format_type == 'html':
            return self.formatters[format_type](data, output_path, additional_data, input_file)
        else:
            return self.formatters[format_type](data, output_path, additional_data)
    
    def _format_csv(self, data: pd.DataFrame, output_path: str, 
                   additional_data: Optional[Dict] = None) -> str:
        """Format data as CSV"""
        data.to_csv(output_path, index=False)
        return output_path
    
    def _format_json(self, data: pd.DataFrame, output_path: str, 
                    additional_data: Optional[Dict] = None) -> str:
        """Format data as JSON"""
        output_data = {
            'messages': data.to_dict('records'),
            'metadata': {
                'total_messages': len(data),
                'timestamp': datetime.now().isoformat(),
                'format': 'json'
            }
        }
        
        if additional_data:
            output_data['analysis'] = additional_data
        
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        
        return output_path
    
    def _format_excel(self, data: pd.DataFrame, output_path: str, 
                     additional_data: Optional[Dict] = None) -> str:
        """Format data as Excel with multiple sheets"""
        try:
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                # Main data sheet
                data.to_excel(writer, sheet_name='Messages', index=False)
                
                # Analysis sheet if additional data provided
                if additional_data:
                    analysis_data = []
                    for key, value in additional_data.items():
                        if isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                analysis_data.append([f"{key}.{sub_key}", str(sub_value)])
                        else:
                            analysis_data.append([key, str(value)])
                    
                    analysis_df = pd.DataFrame(analysis_data, columns=['Metric', 'Value'])
                    analysis_df.to_excel(writer, sheet_name='Analysis', index=False)
            
            return output_path
        except ImportError:
            logger.warning("openpyxl not available, falling back to CSV")
            return self._format_csv(data, output_path.replace('.xlsx', '.csv'), additional_data)
    
    def _format_html(self, data: pd.DataFrame, output_path: str, 
                    additional_data: Optional[Dict] = None, input_file: str = None) -> str:
        """Format data as HTML dashboard"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NAS Log Analysis Dashboard</title>
            <meta charset="utf-8">
            <style>
                * {{ box-sizing: border-box; }}
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 0; 
                    background-color: #f5f5f5; 
                    color: #333;
                    line-height: 1.6;
                }}
                .container {{ 
                    max-width: 1400px; 
                    margin: 0 auto; 
                    padding: 20px; 
                }}
                .header {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white; 
                    padding: 30px; 
                    border-radius: 10px; 
                    margin-bottom: 30px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                .header h1 {{ margin: 0 0 10px 0; font-size: 2.5em; }}
                .header p {{ margin: 5px 0; opacity: 0.9; }}
                .stats-grid {{ 
                    display: grid; 
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
                    gap: 20px; 
                    margin-bottom: 30px; 
                }}
                .stat-card {{ 
                    background: white; 
                    padding: 20px; 
                    border-radius: 10px; 
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    border-left: 4px solid #667eea;
                }}
                .stat-card h3 {{ 
                    margin: 0 0 10px 0; 
                    color: #667eea; 
                    font-size: 1.1em; 
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }}
                .stat-value {{ 
                    font-size: 2em; 
                    font-weight: bold; 
                    color: #333; 
                    margin: 10px 0;
                }}
                .stat-description {{ 
                    color: #666; 
                    font-size: 0.9em; 
                }}
                .section {{ 
                    background: white; 
                    margin: 20px 0; 
                    border-radius: 10px; 
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                .section-header {{ 
                    background: #f8f9fa; 
                    padding: 20px; 
                    border-bottom: 1px solid #e9ecef;
                    font-size: 1.3em;
                    font-weight: 600;
                    color: #495057;
                }}
                .section-content {{ padding: 20px; }}
                .metric-grid {{ 
                    display: grid; 
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
                    gap: 15px; 
                }}
                .metric-item {{ 
                    background: #f8f9fa; 
                    padding: 15px; 
                    border-radius: 8px; 
                    border-left: 3px solid #28a745;
                }}
                .metric-item.warning {{ border-left-color: #ffc107; }}
                .metric-item.error {{ border-left-color: #dc3545; }}
                .metric-label {{ 
                    font-weight: 600; 
                    color: #495057; 
                    margin-bottom: 5px;
                    font-size: 0.9em;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }}
                .metric-value {{ 
                    font-size: 1.1em; 
                    color: #333; 
                    word-break: break-word;
                }}
                .data-table {{ 
                    margin: 20px 0; 
                    overflow-x: auto;
                    max-height: 400px;
                    overflow-y: auto;
                }}
                .data-table table {{
                    border-collapse: collapse; 
                    width: 100%; 
                    font-size: 0.9em;
                }}
                table {{ 
                    border-collapse: collapse; 
                    width: 100%; 
                    font-size: 0.9em;
                }}
                th, td {{ 
                    border: 1px solid #dee2e6; 
                    padding: 12px 8px; 
                    text-align: left; 
                }}
                th {{ 
                    background-color: #f8f9fa; 
                    font-weight: 600;
                    color: #495057;
                }}
                tr:nth-child(even) {{ background-color: #f8f9fa; }}
                .timestamp {{ font-family: monospace; font-size: 0.85em; }}
                .status-success {{ color: #28a745; font-weight: 600; }}
                .status-warning {{ color: #ffc107; font-weight: 600; }}
                .status-error {{ color: #dc3545; font-weight: 600; }}
                .collapsible {{ 
                    cursor: pointer; 
                    user-select: none;
                }}
                .collapsible:hover {{ 
                    background-color: #e9ecef; 
                }}
                .collapsible-content {{ 
                    display: none; 
                    padding: 15px; 
                    background-color: #f8f9fa;
                    border-top: 1px solid #dee2e6;
                }}
                .show {{ display: block; }}
                .toggle-icon {{ 
                    float: right; 
                    transition: transform 0.3s;
                }}
                .rotated {{ transform: rotate(90deg); }}
                @media (max-width: 768px) {{
                    .stats-grid {{ grid-template-columns: 1fr; }}
                    .metric-grid {{ grid-template-columns: 1fr; }}
                    .container {{ padding: 10px; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📊 NAS Log Analysis Dashboard</h1>
                    <p>📁 Input File: {os.path.basename(input_file) if input_file else 'Unknown'}</p>
                    <p>📅 Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p>📝 Total Messages Analyzed: {len(data):,}</p>
                </div>
                
                <div class="section">
                    <div class="section-header">
                        <h3>📊 Visualization Tools</h3>
                    </div>
                    <div class="section-content">
                        <div style="display: flex; gap: 15px; flex-wrap: wrap; justify-content: center;">
                            <a href="timeline.html" target="_blank" style="
                                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                color: white;
                                padding: 12px 24px;
                                border-radius: 8px;
                                text-decoration: none;
                                font-weight: 500;
                                display: inline-flex;
                                align-items: center;
                                gap: 8px;
                                transition: all 0.3s ease;
                                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                            " onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 8px rgba(0,0,0,0.2)'" 
                               onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 2px 4px rgba(0,0,0,0.1)'">
                                📈 Timeline View
                            </a>
                            <a href="detailed_timeline.html" target="_blank" style="
                                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                color: white;
                                padding: 12px 24px;
                                border-radius: 8px;
                                text-decoration: none;
                                font-weight: 500;
                                display: inline-flex;
                                align-items: center;
                                gap: 8px;
                                transition: all 0.3s ease;
                                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                            " onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 8px rgba(0,0,0,0.2)'" 
                               onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 2px 4px rgba(0,0,0,0.1)'">
                                📊 Detailed Timeline
                            </a>
                            <a href="sequence_diagram.html" target="_blank" style="
                                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                color: white;
                                padding: 12px 24px;
                                border-radius: 8px;
                                text-decoration: none;
                                font-weight: 500;
                                display: inline-flex;
                                align-items: center;
                                gap: 8px;
                                transition: all 0.3s ease;
                                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                            " onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 8px rgba(0,0,0,0.2)'" 
                               onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 2px 4px rgba(0,0,0,0.1)'">
                                🔄 Sequence Diagram
                            </a>
                        </div>
                    </div>
                </div>
        """
        
        # Add summary statistics
        if additional_data and 'summary' in additional_data:
            summary = additional_data['summary']
            html_content += f"""
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>System Health</h3>
                        <div class="stat-value status-{'success' if summary.get('health_score', 0) >= 80 else 'warning' if summary.get('health_score', 0) >= 60 else 'error'}">
                            {summary.get('health_score', 'N/A')}%
                        </div>
                        <div class="stat-description">Overall system health score</div>
                    </div>
                    <div class="stat-card">
                        <h3>Severity Level</h3>
                        <div class="stat-value status-{'success' if summary.get('severity_level') == 'normal' else 'warning' if summary.get('severity_level') == 'warning' else 'error'}">
                            {summary.get('severity_level', 'N/A').title()}
                        </div>
                        <div class="stat-description">Current system status</div>
                    </div>
                    <div class="stat-card">
                        <h3>Failure Rate</h3>
                        <div class="stat-value status-{'success' if summary.get('failure_rate', 0) <= 5 else 'warning' if summary.get('failure_rate', 0) <= 15 else 'error'}">
                            {summary.get('failure_rate', 0):.1f}%
                        </div>
                        <div class="stat-description">Message failure rate</div>
                    </div>
                    <div class="stat-card">
                        <h3>Active Sessions</h3>
                        <div class="stat-value">{summary.get('total_sessions', 0)}</div>
                        <div class="stat-description">Total sessions detected</div>
                    </div>
                </div>
            """
        
        # Add detailed analysis sections
        if additional_data:
            html_content += self._format_analysis_sections(additional_data)
        
        # Add data table with collapsible functionality
        html_content += f"""
                <div class="section">
                    <div class="section-header collapsible" onclick="toggleSection('data-table')">
                        📋 Message Data Table
                        <span class="toggle-icon">▶</span>
                    </div>
                    <div class="section-content collapsible-content" id="data-table">
                        <div class="data-table">
                            {data.fillna('').to_html(classes='data-table', index=False)}
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                function toggleSection(id) {{
                    const content = document.getElementById(id);
                    const header = content.previousElementSibling;
                    const icon = header.querySelector('.toggle-icon');
                    
                    if (content.classList.contains('show')) {{
                        content.classList.remove('show');
                        icon.classList.remove('rotated');
                    }} else {{
                        content.classList.add('show');
                        icon.classList.add('rotated');
                    }}
                }}
                
                // Auto-expand first section
                document.addEventListener('DOMContentLoaded', function() {{
                    const firstSection = document.querySelector('.collapsible-content');
                    if (firstSection) {{
                        firstSection.classList.add('show');
                        firstSection.previousElementSibling.querySelector('.toggle-icon').classList.add('rotated');
                    }}
                }});
            </script>
        </body>
        </html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return output_path

    def _format_analysis_sections(self, additional_data: Dict) -> str:
        """Format analysis data into organized HTML sections"""
        html_content = ""
        
        # Performance Analysis Section
        if 'performance' in additional_data:
            perf = additional_data['performance']
            html_content += """
                <div class="section">
                    <div class="section-header collapsible" onclick="toggleSection('performance')">
                        ⚡ Performance Analysis
                        <span class="toggle-icon">▶</span>
                    </div>
                    <div class="section-content collapsible-content" id="performance">
                        <div class="metric-grid">
            """
            # Response times
            if 'response_times' in perf:
                html_content += '<div class="metric-item">'
                html_content += '<div class="metric-label">Response Times</div>'
                html_content += '<div class="metric-value">'
                for flow, times in perf['response_times'].items():
                    avg_time = sum(times) / len(times) if times else 0
                    html_content += f'<div><strong>{flow}:</strong> {avg_time:.3f}s avg</div>'
                html_content += '</div></div>'
            # Success rates
            if 'success_rates' in perf:
                html_content += '<div class="metric-item">'
                html_content += '<div class="metric-label">Success Rates</div>'
                html_content += '<div class="metric-value">'
                for msg_type, rate in perf['success_rates'].items():
                    status_class = 'success' if rate >= 90 else 'warning' if rate >= 70 else 'error'
                    html_content += f'<div class="status-{status_class}">{msg_type}: {rate:.1f}%</div>'
                html_content += '</div></div>'
            # Message distribution
            if 'message_distribution' in perf:
                html_content += '<div class="metric-item">'
                html_content += '<div class="metric-label">Message Distribution</div>'
                html_content += '<div class="metric-value">'
                for msg_type, count in perf['message_distribution'].items():
                    html_content += f'<div>{msg_type}: {count}</div>'
                html_content += '</div></div>'
            # Timing statistics
            if 'timing_statistics' in perf:
                timing = perf['timing_statistics']
                html_content += '<div class="metric-item">'
                html_content += '<div class="metric-label">Timing Statistics</div>'
                html_content += '<div class="metric-value">'
                html_content += f'<div>Session Duration: {timing.get("session_duration_seconds", 0):.2f}s</div>'
                html_content += f'<div>Message Frequency: {timing.get("message_frequency_per_second", 0):.2f}/s</div>'
                html_content += f'<div>Avg Time Between Messages: {timing.get("avg_time_between_messages_seconds", 0):.3f}s</div>'
                html_content += '</div></div>'
            html_content += """
                        </div>
                    </div>
                </div>
            """
        # Failure Analysis Section
        if 'failures' in additional_data:
            failures = additional_data['failures']
            html_content += """
                <div class="section">
                    <div class="section-header collapsible" onclick="toggleSection('failures')">
                        ⚠️ Failure Analysis
                        <span class="toggle-icon">▶</span>
                    </div>
                    <div class="section-content collapsible-content" id="failures">
                        <div class="metric-grid">
            """
            # Failure summary
            if 'failure_summary' in failures:
                summary = failures['failure_summary']
                html_content += '<div class="metric-item">'
                html_content += '<div class="metric-label">Failure Summary</div>'
                html_content += '<div class="metric-value">'
                html_content += f'<div>Total Failures: {summary.get("total_failures", 0)}</div>'
                html_content += f'<div>Failure Rate: {summary.get("failure_rate", 0):.1f}%</div>'
                html_content += f'<div>Most Common: {summary.get("most_common_failure", "None")}</div>'
                html_content += '</div></div>'
            # Failure types
            if 'failure_types' in failures and failures['failure_types']:
                html_content += '<div class="metric-item">'
                html_content += '<div class="metric-label">Failure Types</div>'
                html_content += '<div class="metric-value">'
                for failure_type, count in failures['failure_types'].items():
                    html_content += f'<div>{failure_type}: {count}</div>'
                html_content += '</div></div>'
            # Recommendations
            if 'recommendations' in failures:
                html_content += '<div class="metric-item">'
                html_content += '<div class="metric-label">Recommendations</div>'
                html_content += '<div class="metric-value">'
                for rec in failures['recommendations']:
                    html_content += f'<div>• {rec}</div>'
                html_content += '</div></div>'
            html_content += """
                        </div>
                    </div>
                </div>
            """
        # Session Analysis Section
        if 'sessions' in additional_data:
            sessions = additional_data['sessions']
            html_content += """
                <div class="section">
                    <div class="section-header collapsible" onclick="toggleSection('sessions')">
                        🔄 Session Analysis
                        <span class="toggle-icon">▶</span>
                    </div>
                    <div class="section-content collapsible-content" id="sessions">
                        <div class="metric-grid">
            """
            # Session summary
            html_content += '<div class="metric-item">'
            html_content += '<div class="metric-label">Session Summary</div>'
            html_content += '<div class="metric-value">'
            html_content += f'<div>Total Sessions: {sessions.get("total_sessions", 0)}</div>'
            if 'session_durations' in sessions:
                avg_duration = sum(sessions['session_durations']) / len(sessions['session_durations']) if sessions['session_durations'] else 0
                html_content += f'<div>Average Duration: {avg_duration:.2f}s</div>'
            if 'messages_per_session' in sessions:
                avg_messages = sum(sessions['messages_per_session']) / len(sessions['messages_per_session']) if sessions['messages_per_session'] else 0
                html_content += f'<div>Average Messages: {avg_messages:.1f}</div>'
            html_content += '</div></div>'
            # Session types
            if 'session_types' in sessions:
                html_content += '<div class="metric-item">'
                html_content += '<div class="metric-label">Session Types</div>'
                html_content += '<div class="metric-value">'
                for session_type, count in sessions['session_types'].items():
                    html_content += f'<div>{session_type.replace("_", " ").title()}: {count}</div>'
                html_content += '</div></div>'
            html_content += """
                        </div>
                    </div>
                </div>
            """
        # State Analysis Section
        if 'state_analysis' in additional_data:
            state_analysis = additional_data['state_analysis']
            html_content += """
                <div class="section">
                    <div class="section-header collapsible" onclick="toggleSection('state-analysis')">
                        🔄 State Analysis
                        <span class="toggle-icon">▶</span>
                    </div>
                    <div class="section-content collapsible-content" id="state-analysis">
                        <div class="metric-grid">
            """
            # State summary
            if 'state_summary' in state_analysis:
                summary = state_analysis['state_summary']
                html_content += '<div class="metric-item">'
                html_content += '<div class="metric-label">State Summary</div>'
                html_content += '<div class="metric-value">'
                html_content += f'<div>Initial EMM: {summary.get("initial_emm_state", "Unknown")}</div>'
                html_content += f'<div>Final EMM: {summary.get("final_emm_state", "Unknown")}</div>'
                html_content += f'<div>Initial ESM: {summary.get("initial_esm_state", "Unknown")}</div>'
                html_content += f'<div>Final ESM: {summary.get("final_esm_state", "Unknown")}</div>'
                html_content += f'<div>Total Changes: {summary.get("total_state_changes", 0)}</div>'
                html_content += '</div></div>'
            # State transitions
            if 'state_summary' in state_analysis and 'state_transitions' in state_analysis['state_summary']:
                transitions = state_analysis['state_summary']['state_transitions']
                html_content += '<div class="metric-item">'
                html_content += '<div class="metric-label">State Transitions</div>'
                html_content += '<div class="metric-value">'
                for transition in transitions[:5]:  # Show first 5 transitions
                    html_content += f'<div>• {transition.get("timestamp", "")}: {transition.get("action", "")}</div>'
                if len(transitions) > 5:
                    html_content += f'<div>... and {len(transitions) - 5} more</div>'
                html_content += '</div></div>'
            # State anomalies
            if 'state_summary' in state_analysis and 'state_anomalies' in state_analysis['state_summary']:
                anomalies = state_analysis['state_summary']['state_anomalies']
                if anomalies:
                    html_content += '<div class="metric-item error">'
                    html_content += '<div class="metric-label">State Anomalies</div>'
                    html_content += '<div class="metric-value">'
                    for anomaly in anomalies[:3]:  # Show first 3 anomalies
                        severity = anomaly.get('severity', 'unknown')
                        html_content += f'<div class="status-{severity}">• {anomaly.get("message", "")}</div>'
                    if len(anomalies) > 3:
                        html_content += f'<div>... and {len(anomalies) - 3} more</div>'
                    html_content += '</div></div>'
            html_content += """
                        </div>
                    </div>
                </div>
            """
        return html_content


class SequenceDiagramGenerator:
    """Generates Mermaid.js sequence diagrams for NAS message flows"""
    def __init__(self):
        self.participants = ['UE', 'eNodeB', 'MME']
        self.default_direction_map = {
            'Incoming': ('UE', 'MME'),
            'Outgoing': ('MME', 'UE'),
        }

    def generate_mermaid(self, messages: pd.DataFrame, session_id: str = None) -> str:
        """
        Generate a Mermaid.js sequence diagram for a set of NAS messages.
        Args:
            messages: DataFrame of messages (should be for a single session/conversation)
            session_id: Optional session/conversation ID for labeling
        Returns:
            Mermaid.js sequence diagram as a string
        """
        lines = ["sequenceDiagram"]
        if session_id:
            lines.append(f'    %% Session: {session_id}')
        # Add participants
        for p in self.participants:
            lines.append(f'    participant {p}')
        # Sort messages by timestamp
        messages_sorted = messages.sort_values('timestamp')
        for _, row in messages_sorted.iterrows():
            direction = row.get('direction', 'Outgoing')
            msg_type = row.get('message_type', 'Unknown')
            ts = row.get('timestamp', '')
            # Determine sender/receiver
            sender, receiver = self.default_direction_map.get(direction, ('UE', 'MME'))
            # Compose message line
            label = f"{msg_type} ({ts})"
            lines.append(f'    {sender}->>{receiver}: {label}')
        return '\n'.join(lines)

    def save_mermaid_html(self, mermaid_code: str, output_path: str, title: str = "NAS Sequence Diagram"):
        """
        Save sequence diagram as a standalone HTML file with pure HTML/CSS.
        """
        # Parse the mermaid code to extract sequence data
        sequence_data = self._parse_mermaid_sequence(mermaid_code)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='utf-8'>
            <title>{title}</title>
            <style>
                * {{ box-sizing: border-box; }}
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 20px; 
                    background-color: #f5f5f5; 
                    color: #333;
                    line-height: 1.6;
                }}
                .container {{ 
                    max-width: 1400px; 
                    margin: 0 auto; 
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                .header {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white; 
                    padding: 30px; 
                    text-align: center;
                }}
                .header h1 {{ margin: 0; font-size: 2.5em; }}
                .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
                .sequence-container {{
                    padding: 30px;
                    overflow-x: auto;
                }}
                .sequence-diagram {{
                    position: relative;
                    min-height: 400px;
                    margin: 20px 0;
                }}
                .participant {{
                    position: absolute;
                    top: 0;
                    width: 120px;
                    text-align: center;
                    font-weight: 600;
                    color: #495057;
                    transform: translateX(-50%);
                }}
                .participant-line {{
                    position: absolute;
                    top: 40px;
                    width: 2px;
                    height: 100%;
                    background: #667eea;
                }}
                .message {{
                    position: absolute;
                    height: 60px;
                    display: flex;
                    align-items: center;
                    font-size: 0.9em;
                }}
                .message-line {{
                    position: absolute;
                    height: 2px;
                    background: #333;
                    top: 50%;
                    transform: translateY(-50%);
                }}
                .message-line.arrow-right::after {{
                    content: '';
                    position: absolute;
                    right: -8px;
                    top: -3px;
                    width: 0;
                    height: 0;
                    border-left: 8px solid #333;
                    border-top: 4px solid transparent;
                    border-bottom: 4px solid transparent;
                }}
                .message-line.arrow-left::after {{
                    content: '';
                    position: absolute;
                    left: -8px;
                    top: -3px;
                    width: 0;
                    height: 0;
                    border-right: 8px solid #333;
                    border-top: 4px solid transparent;
                    border-bottom: 4px solid transparent;
                }}
                .message-text {{
                    position: absolute;
                    top: -30px;
                    left: 50%;
                    transform: translateX(-50%);
                    background: #f8f9fa;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.8em;
                    white-space: nowrap;
                    border: 1px solid #dee2e6;
                    z-index: 10;
                }}
                .activation {{
                    position: absolute;
                    width: 8px;
                    background: #667eea;
                    border-radius: 2px;
                }}
                .legend {{
                    margin-top: 30px;
                    padding: 20px;
                    background: #f8f9fa;
                    border-radius: 8px;
                    border-left: 4px solid #667eea;
                }}
                .legend h3 {{
                    margin: 0 0 15px 0;
                    color: #495057;
                }}
                .legend-item {{
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    margin: 8px 0;
                }}
                .legend-symbol {{
                    width: 20px;
                    height: 2px;
                    background: #333;
                }}
                .legend-symbol.arrow::after {{
                    content: '';
                    position: absolute;
                    right: -8px;
                    top: -3px;
                    width: 0;
                    height: 0;
                    border-left: 8px solid #333;
                    border-top: 4px solid transparent;
                    border-bottom: 4px solid transparent;
                }}
                @media (max-width: 768px) {{
                    .sequence-container {{ padding: 15px; }}
                    .participant {{ width: 80px; font-size: 0.8em; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔄 {title}</h1>
                    <p>NAS Protocol Message Flow Visualization</p>
                </div>
                
                <div class="sequence-container">
                    <div class="sequence-diagram" style="height: {max(400, len(sequence_data.get('messages', [])) * 80 + 100)}px;">
                        {self._generate_html_sequence(sequence_data)}
                    </div>
                    
                    <div class="legend">
                        <h3>📋 Legend</h3>
                        <div class="legend-item">
                            <div class="legend-symbol"></div>
                            <span>Message flow between entities</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-symbol" style="background: #667eea;"></div>
                            <span>Entity activation/lifecycle</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-symbol arrow"></div>
                            <span>Message direction (arrow indicates target)</span>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        with open(output_path, 'w') as f:
            f.write(html)

    def _parse_mermaid_sequence(self, mermaid_code: str) -> Dict:
        """Parse Mermaid sequence diagram code to extract participants and messages"""
        import re
        
        participants = []
        messages = []
        
        # Extract participants (both formats: "participant X" and "participant X as Y")
        participant_pattern = r'participant\s+(\w+)(?:\s+as\s+(.+))?'
        for match in re.finditer(participant_pattern, mermaid_code):
            participant_id = match.group(1)
            participant_name = match.group(2) if match.group(2) else participant_id
            participants.append({
                'id': participant_id,
                'name': participant_name.strip()
            })
        
        # Extract messages (both -> and ->> formats)
        message_pattern = r'(\w+)\s*->+>\s*(\w+)\s*:\s*(.+)'
        for match in re.finditer(message_pattern, mermaid_code):
            messages.append({
                'from': match.group(1),
                'to': match.group(2),
                'text': match.group(3).strip()
            })
        
        return {
            'participants': participants,
            'messages': messages
        }
    
    def _generate_html_sequence(self, sequence_data: Dict) -> str:
        """Generate HTML for sequence diagram"""
        participants = sequence_data.get('participants', [])
        messages = sequence_data.get('messages', [])
        
        if not participants:
            return '<div style="text-align: center; padding: 50px; color: #666;">No sequence data available</div>'
        
        # Calculate positions
        participant_width = 120
        total_width = len(participants) * participant_width
        message_spacing = 80
        
        html_parts = []
        
        # Generate participants
        for i, participant in enumerate(participants):
            x_pos = i * participant_width + participant_width // 2
            html_parts.append(f'''
                <div class="participant" style="left: {x_pos}px;">
                    {participant['name']}
                </div>
                <div class="participant-line" style="left: {x_pos}px; transform: translateX(-50%);"></div>
            ''')
        
        # Generate messages
        for i, message in enumerate(messages):
            from_idx = next((j for j, p in enumerate(participants) if p['id'] == message['from']), 0)
            to_idx = next((j for j, p in enumerate(participants) if p['id'] == message['to']), 0)
            
            from_x = from_idx * participant_width + participant_width // 2
            to_x = to_idx * participant_width + participant_width // 2
            y_pos = 100 + i * message_spacing
            
            # Determine arrow direction
            arrow_class = 'arrow-right' if from_x < to_x else 'arrow-left'
            
            # Calculate line width and position
            if from_x < to_x:
                line_left = from_x
                line_width = to_x - from_x
                label_center = from_x + (to_x - from_x) // 2
            else:
                line_left = to_x
                line_width = from_x - to_x
                label_center = to_x + (from_x - to_x) // 2
            
            html_parts.append(f'''
                <div class="message" style="top: {y_pos}px;">
                    <div class="message-line {arrow_class}" style="left: {line_left}px; width: {line_width}px;"></div>
                    <div class="message-text" style="left: {label_center}px;">{message['text']}</div>
                </div>
            ''')
        
        return '\n'.join(html_parts)


class TimelineVisualizer:
    """Creates interactive timeline visualizations for NAS message sessions"""
    
    def __init__(self):
        self.color_map = {
            'Attach request': '#1f77b4',
            'Attach accept': '#2ca02c', 
            'Attach complete': '#2ca02c',
            'Detach request': '#d62728',
            'Detach accept': '#d62728',
            'Security mode command': '#ff7f0e',
            'Security mode complete': '#ff7f0e',
            'Activate default EPS bearer context request': '#9467bd',
            'Activate default EPS bearer context accept': '#9467bd',
            'EMM State': '#8c564b',
            'ESM Bearer Context State': '#e377c2'
        }
    
    def create_timeline(self, messages: pd.DataFrame, output_path: str, title: str = "NAS Session Timeline"):
        """
        Create an interactive timeline visualization of NAS messages
        
        Args:
            messages: DataFrame with parsed NAS messages
            output_path: Path to save the HTML timeline
            title: Title for the timeline
        """
        if len(messages) == 0:
            logger.warning("No messages to visualize in timeline")
            return
        
        # Ensure timestamp column exists and convert to datetime
        if 'timestamp' not in messages.columns:
            logger.error("Timestamp column not found for timeline visualization")
            return
        
        # Convert timestamps to datetime
        messages = messages.copy()
        messages['timestamp'] = pd.to_datetime(messages['timestamp'])
        
        # Sort by timestamp
        messages_sorted = messages.sort_values('timestamp')
        
        # Create timeline figure
        fig = go.Figure()
        
        # Add timeline traces for each message type
        for msg_type in messages_sorted['message_type'].unique():
            type_messages = messages_sorted[messages_sorted['message_type'] == msg_type]
            
            # Get color for this message type
            color = self.color_map.get(msg_type, '#636363')
            
            # Create hover text with details
            hover_text = []
            for _, row in type_messages.iterrows():
                details = f"Type: {row['message_type']}<br>"
                if pd.notna(row.get('direction')):
                    details += f"Direction: {row['direction']}<br>"
                if pd.notna(row.get('bearer_id')):
                    details += f"Bearer ID: {row['bearer_id']}<br>"
                if pd.notna(row.get('correlation_id')):
                    details += f"Correlation: {row['correlation_id']}<br>"
                details += f"Time: {row['timestamp'].strftime('%H:%M:%S.%f')[:-3]}"
                hover_text.append(details)
            
            # Add scatter trace for this message type
            fig.add_trace(go.Scatter(
                x=type_messages['timestamp'],
                y=[msg_type] * len(type_messages),
                mode='markers',
                name=msg_type,
                marker=dict(
                    size=10,
                    color=color,
                    symbol='circle'
                ),
                hovertext=hover_text,
                hoverinfo='text',
                showlegend=True
            ))
        
        # Update layout
        fig.update_layout(
            title=title,
            xaxis_title="Time",
            yaxis_title="Message Type",
            height=600,
            hovermode='closest',
            showlegend=True,
            legend=dict(
                yanchor="top",
                y=1.02,
                xanchor="left",
                x=1.02,
                bgcolor='rgba(255,255,255,0.8)',
                bordercolor='rgba(0,0,0,0.2)',
                borderwidth=1
            )
        )
        
        # Update x-axis to show time properly
        fig.update_xaxes(
            tickformat='%H:%M:%S.%L',
            tickangle=45
        )
        
        # Update y-axis
        fig.update_yaxes(
            tickmode='array',
            ticktext=messages_sorted['message_type'].unique(),
            tickvals=messages_sorted['message_type'].unique()
        )
        
        # Save as interactive HTML
        fig.write_html(output_path, include_plotlyjs=True)
        logger.info(f"Timeline visualization saved to {output_path}")
    
    def create_detailed_timeline(self, messages: pd.DataFrame, output_path: str, title: str = "Detailed NAS Timeline"):
        """
        Create a more detailed timeline with subplots for different aspects
        
        Args:
            messages: DataFrame with parsed NAS messages
            output_path: Path to save the HTML timeline
            title: Title for the timeline
        """
        if len(messages) == 0:
            logger.warning("No messages to visualize in detailed timeline")
            return
        
        # Ensure timestamp column exists and convert to datetime
        if 'timestamp' not in messages.columns:
            logger.error("Timestamp column not found for detailed timeline visualization")
            return
        
        # Convert timestamps to datetime
        messages = messages.copy()
        messages['timestamp'] = pd.to_datetime(messages['timestamp'])
        
        # Sort by timestamp
        messages_sorted = messages.sort_values('timestamp')
        
        # Create subplots
        fig = make_subplots(
            rows=3, cols=1,
            subplot_titles=('Message Timeline', 'Direction Analysis', 'Correlation Groups'),
            vertical_spacing=0.1,
            row_heights=[0.5, 0.25, 0.25]
        )
        
        # Main timeline (top subplot)
        for msg_type in messages_sorted['message_type'].unique():
            type_messages = messages_sorted[messages_sorted['message_type'] == msg_type]
            color = self.color_map.get(msg_type, '#636363')
            
            hover_text = []
            for _, row in type_messages.iterrows():
                details = f"Type: {row['message_type']}<br>"
                if pd.notna(row.get('direction')):
                    details += f"Direction: {row['direction']}<br>"
                if pd.notna(row.get('bearer_id')):
                    details += f"Bearer ID: {row['bearer_id']}<br>"
                details += f"Time: {row['timestamp'].strftime('%H:%M:%S.%f')[:-3]}"
                hover_text.append(details)
            
            fig.add_trace(
                go.Scatter(
                    x=type_messages['timestamp'],
                    y=[msg_type] * len(type_messages),
                    mode='markers',
                    name=msg_type,
                    marker=dict(size=8, color=color),
                    hovertext=hover_text,
                    hoverinfo='text',
                    showlegend=True
                ),
                row=1, col=1
            )
        
        # Direction analysis (middle subplot)
        if 'direction' in messages_sorted.columns:
            for direction in messages_sorted['direction'].unique():
                if pd.notna(direction):
                    dir_messages = messages_sorted[messages_sorted['direction'] == direction]
                    color = '#1f77b4' if direction == 'Incoming' else '#ff7f0e'
                    
                    fig.add_trace(
                        go.Scatter(
                            x=dir_messages['timestamp'],
                            y=[direction] * len(dir_messages),
                            mode='markers',
                            name=f"{direction} Messages",
                            marker=dict(size=6, color=color),
                            showlegend=False
                        ),
                        row=2, col=1
                    )
        
        # Correlation groups (bottom subplot)
        if 'correlation_id' in messages_sorted.columns:
            correlation_groups = messages_sorted[messages_sorted['correlation_id'].notna()].groupby('correlation_id')
            for i, (corr_id, group) in enumerate(correlation_groups):
                color = px.colors.qualitative.Set3[i % len(px.colors.qualitative.Set3)]
                
                fig.add_trace(
                    go.Scatter(
                        x=group['timestamp'],
                        y=[f"Group {i+1}"] * len(group),
                        mode='markers',
                        name=f"Correlation {corr_id[:20]}...",
                        marker=dict(size=6, color=color),
                        showlegend=False
                    ),
                    row=3, col=1
                )
        
        # Update layout
        fig.update_layout(
            title=title,
            height=800,
            hovermode='closest',
            showlegend=True,
            legend=dict(
                yanchor="top",
                y=1.02,
                xanchor="left",
                x=1.02,
                bgcolor='rgba(255,255,255,0.8)',
                bordercolor='rgba(0,0,0,0.2)',
                borderwidth=1
            )
        )
        
        # Update axes
        fig.update_xaxes(title_text="Time", row=3, col=1)
        fig.update_yaxes(title_text="Message Type", row=1, col=1)
        fig.update_yaxes(title_text="Direction", row=2, col=1)
        fig.update_yaxes(title_text="Correlation Group", row=3, col=1)
        
        # Save as interactive HTML
        fig.write_html(output_path, include_plotlyjs=True)
        logger.info(f"Detailed timeline visualization saved to {output_path}")


class SessionStateMachine:
    """Tracks NAS protocol states and provides state transition analysis"""
    
    def __init__(self):
        # EMM States (3GPP TS 24.301)
        self.emm_states = {
            1: "EMM-DEREGISTERED",
            2: "EMM-REGISTERED",
            3: "EMM-TRACKING-AREA-UPDATING-INITIATED",
            4: "EMM-SERVICE-REQUEST-INITIATED",
            5: "EMM-DEREGISTERED-INITIATED"
        }
        
        # ESM States (3GPP TS 24.301)
        self.esm_states = {
            1: "ESM-INACTIVE",
            2: "ESM-PDP-CONTEXT-INACTIVE",
            3: "ESM-PDP-CONTEXT-ACTIVE"
        }
        
        # State transition rules
        self.state_transitions = {
            'EMM-DEREGISTERED': ['EMM-REGISTERED', 'EMM-DEREGISTERED-INITIATED'],
            'EMM-REGISTERED': ['EMM-DEREGISTERED', 'EMM-TRACKING-AREA-UPDATING-INITIATED', 'EMM-SERVICE-REQUEST-INITIATED'],
            'EMM-TRACKING-AREA-UPDATING-INITIATED': ['EMM-REGISTERED', 'EMM-DEREGISTERED'],
            'EMM-SERVICE-REQUEST-INITIATED': ['EMM-REGISTERED', 'EMM-DEREGISTERED'],
            'EMM-DEREGISTERED-INITIATED': ['EMM-DEREGISTERED']
        }
        
        # Message to state mapping
        self.message_state_mapping = {
            'Attach request': {'emm': 'EMM-DEREGISTERED', 'action': 'initiate_attach'},
            'Attach accept': {'emm': 'EMM-REGISTERED', 'action': 'complete_attach'},
            'Attach reject': {'emm': 'EMM-DEREGISTERED', 'action': 'attach_failed'},
            'Detach request': {'emm': 'EMM-DEREGISTERED-INITIATED', 'action': 'initiate_detach'},
            'Detach accept': {'emm': 'EMM-DEREGISTERED', 'action': 'complete_detach'},
            'Service Request': {'emm': 'EMM-SERVICE-REQUEST-INITIATED', 'action': 'initiate_service'},
            'Service Accept': {'emm': 'EMM-REGISTERED', 'action': 'complete_service'},
            'Service Reject': {'emm': 'EMM-REGISTERED', 'action': 'service_failed'},
            'Tracking Area Update request': {'emm': 'EMM-TRACKING-AREA-UPDATING-INITIATED', 'action': 'initiate_tau'},
            'Tracking Area Update accept': {'emm': 'EMM-REGISTERED', 'action': 'complete_tau'},
            'Tracking Area Update reject': {'emm': 'EMM-REGISTERED', 'action': 'tau_failed'},
            'Activate default EPS bearer context request': {'esm': 'ESM-PDP-CONTEXT-ACTIVE', 'action': 'initiate_bearer_activation'},
            'Activate default EPS bearer context accept': {'esm': 'ESM-PDP-CONTEXT-ACTIVE', 'action': 'complete_bearer_activation'},
            'Activate default EPS bearer context reject': {'esm': 'ESM-PDP-CONTEXT-INACTIVE', 'action': 'bearer_activation_failed'},
            'Deactivate EPS bearer context request': {'esm': 'ESM-PDP-CONTEXT-INACTIVE', 'action': 'initiate_bearer_deactivation'},
            'Deactivate EPS bearer context accept': {'esm': 'ESM-PDP-CONTEXT-INACTIVE', 'action': 'complete_bearer_deactivation'},
            'Security mode command': {'action': 'security_negotiation'},
            'Security mode complete': {'action': 'security_established'},
            'Security mode reject': {'action': 'security_failed'}
        }
    
    def analyze_session_states(self, messages: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze state transitions in a NAS session
        
        Args:
            messages: DataFrame with parsed NAS messages
            
        Returns:
            Dictionary containing state analysis results
        """
        logger.info("Starting session state analysis")
        
        if len(messages) == 0:
            return {}
        
        # Sort messages by timestamp
        messages_sorted = messages.sort_values('timestamp')
        
        # Track state transitions
        state_history = []
        current_emm_state = "EMM-DEREGISTERED"
        current_esm_state = "ESM-INACTIVE"
        
        # Analyze each message
        for idx, row in messages_sorted.iterrows():
            message_type = row.get('message_type', '')
            direction = row.get('direction', '')
            timestamp = row.get('timestamp')
            
            # Get state mapping for this message
            state_mapping = self.message_state_mapping.get(message_type, {})
            
            # Track state transition
            previous_emm_state = current_emm_state
            previous_esm_state = current_esm_state
            
            # Update EMM state
            if 'emm' in state_mapping:
                current_emm_state = state_mapping['emm']
            
            # Update ESM state
            if 'esm' in state_mapping:
                current_esm_state = state_mapping['esm']
            
            # Record state transition
            state_record = {
                'timestamp': timestamp,
                'message_type': message_type,
                'direction': direction,
                'previous_emm_state': previous_emm_state,
                'current_emm_state': current_emm_state,
                'previous_esm_state': previous_esm_state,
                'current_esm_state': current_esm_state,
                'action': state_mapping.get('action', 'unknown'),
                'emm_state_changed': previous_emm_state != current_emm_state,
                'esm_state_changed': previous_esm_state != current_esm_state
            }
            
            state_history.append(state_record)
        
        # Analyze state transitions
        state_analysis = self._analyze_state_transitions(state_history)
        
        # Generate state summary
        state_summary = {
            'initial_emm_state': state_history[0]['previous_emm_state'] if state_history else 'unknown',
            'final_emm_state': state_history[-1]['current_emm_state'] if state_history else 'unknown',
            'initial_esm_state': state_history[0]['previous_esm_state'] if state_history else 'unknown',
            'final_esm_state': state_history[-1]['current_esm_state'] if state_history else 'unknown',
            'total_state_changes': len([s for s in state_history if s['emm_state_changed'] or s['esm_state_changed']]),
            'emm_state_changes': len([s for s in state_history if s['emm_state_changed']]),
            'esm_state_changes': len([s for s in state_history if s['esm_state_changed']]),
            'session_duration': self._calculate_session_duration(state_history),
            'state_transitions': state_analysis['transitions'],
            'state_anomalies': state_analysis['anomalies'],
            'state_recommendations': state_analysis['recommendations']
        }
        
        logger.info(f"State analysis complete. Found {state_summary['total_state_changes']} state changes")
        return {
            'state_history': state_history,
            'state_summary': state_summary
        }
    
    def _analyze_state_transitions(self, state_history: List[Dict]) -> Dict[str, Any]:
        """Analyze state transitions for anomalies and patterns"""
        transitions = []
        anomalies = []
        
        for i, state in enumerate(state_history):
            if state['emm_state_changed'] or state['esm_state_changed']:
                transition = {
                    'timestamp': state['timestamp'],
                    'message_type': state['message_type'],
                    'emm_transition': f"{state['previous_emm_state']} -> {state['current_emm_state']}" if state['emm_state_changed'] else None,
                    'esm_transition': f"{state['previous_esm_state']} -> {state['current_esm_state']}" if state['esm_state_changed'] else None,
                    'action': state['action']
                }
                transitions.append(transition)
                
                # Check for anomalies
                anomaly = self._check_state_anomaly(state, state_history[:i])
                if anomaly:
                    anomalies.append(anomaly)
        
        # Generate recommendations
        recommendations = self._generate_state_recommendations(transitions, anomalies)
        
        return {
            'transitions': transitions,
            'anomalies': anomalies,
            'recommendations': recommendations
        }
    
    def _check_state_anomaly(self, current_state: Dict, previous_states: List[Dict]) -> Optional[Dict]:
        """Check for state transition anomalies"""
        message_type = current_state['message_type']
        current_emm = current_state['current_emm_state']
        previous_emm = current_state['previous_emm_state']
        
        # Check for invalid transitions
        if previous_emm in self.state_transitions:
            valid_transitions = self.state_transitions[previous_emm]
            if current_emm not in valid_transitions:
                return {
                    'type': 'invalid_transition',
                    'message': f"Invalid EMM transition: {previous_emm} -> {current_emm}",
                    'timestamp': current_state['timestamp'],
                    'message_type': message_type,
                    'severity': 'high'
                }
        
        # Check for unexpected states
        if current_emm == "EMM-DEREGISTERED" and message_type in ['Service Request', 'Tracking Area Update request']:
            return {
                'type': 'unexpected_message',
                'message': f"Unexpected {message_type} in EMM-DEREGISTERED state",
                'timestamp': current_state['timestamp'],
                'message_type': message_type,
                'severity': 'medium'
            }
        
        # Check for missing security establishment
        if message_type in ['Attach accept', 'Service Accept'] and not self._has_security_established(previous_states):
            return {
                'type': 'missing_security',
                'message': f"Security not established before {message_type}",
                'timestamp': current_state['timestamp'],
                'message_type': message_type,
                'severity': 'medium'
            }
        
        return None
    
    def _has_security_established(self, previous_states: List[Dict]) -> bool:
        """Check if security has been established in previous states"""
        for state in previous_states:
            if state['message_type'] == 'Security mode complete':
                return True
        return False
    
    def _calculate_session_duration(self, state_history: List[Dict]) -> float:
        """Calculate total session duration"""
        if len(state_history) < 2:
            return 0.0
        
        start_time = pd.to_datetime(state_history[0]['timestamp'])
        end_time = pd.to_datetime(state_history[-1]['timestamp'])
        duration = (end_time - start_time).total_seconds()
        return duration
    
    def _generate_state_recommendations(self, transitions: List[Dict], anomalies: List[Dict]) -> List[str]:
        """Generate recommendations based on state analysis"""
        recommendations = []
        
        # Check for successful session completion
        if transitions:
            final_transition = transitions[-1]
            if 'EMM-REGISTERED' in str(final_transition):
                recommendations.append("Session completed successfully with UE registered")
            elif 'EMM-DEREGISTERED' in str(final_transition):
                recommendations.append("Session ended with UE deregistered")
        
        # Check for anomalies
        if anomalies:
            high_severity = [a for a in anomalies if a['severity'] == 'high']
            if high_severity:
                recommendations.append(f"Found {len(high_severity)} high-severity state anomalies - review session")
            
            medium_severity = [a for a in anomalies if a['severity'] == 'medium']
            if medium_severity:
                recommendations.append(f"Found {len(medium_severity)} medium-severity state anomalies - monitor session")
        
        # Check for security issues
        security_transitions = [t for t in transitions if 'security' in t['action']]
        if not security_transitions:
            recommendations.append("No security establishment detected - verify security configuration")
        
        # Check for bearer issues
        bearer_transitions = [t for t in transitions if 'bearer' in t['action']]
        if bearer_transitions:
            failed_bearer = [t for t in bearer_transitions if 'failed' in t['action']]
            if failed_bearer:
                recommendations.append(f"Bearer activation failed {len(failed_bearer)} times - check QoS configuration")
        
        if not recommendations:
            recommendations.append("State transitions appear normal - no issues detected")
        
        return recommendations


class AdvancedAnalyzer:
    """Main analyzer class that combines all analysis capabilities"""
    
    def __init__(self):
        self.flow_analyzer = MessageFlowAnalyzer()
        self.apn_decoder = APNDecoder()
        self.performance_analyzer = EnhancedPerformanceAnalyzer()
        self.output_formatter = OutputFormatter()
        self.sequence_diagram_generator = SequenceDiagramGenerator()
        self.timeline_visualizer = TimelineVisualizer()
        self.state_machine = SessionStateMachine()
    
    def analyze_messages(self, messages: pd.DataFrame, output_dir: str, 
                        output_formats: List[str] = ['csv'],
                        generate_sequence_diagram: bool = False,
                        generate_timeline: bool = False,
                        input_file: str = None) -> Dict[str, str]:
        """
        Perform comprehensive analysis on NAS messages
        
        Args:
            messages: DataFrame with parsed NAS messages
            output_dir: Directory to save output files
            output_formats: List of output formats to generate
            
        Returns:
            Dictionary mapping format types to output file paths
        """
        logger.info("Starting comprehensive message analysis")
        
        # Step 1: Correlate messages
        correlated_messages = self.flow_analyzer.correlate_messages(messages)
        
        # Step 2: Decode APN names
        enhanced_messages = self.apn_decoder.enhance_messages_with_apn(correlated_messages)
        
        # Step 3: Calculate comprehensive performance metrics
        comprehensive_metrics = self.performance_analyzer.calculate_comprehensive_metrics(enhanced_messages)
        
        # Step 4: Analyze session states
        state_analysis = self.state_machine.analyze_session_states(enhanced_messages)
        
        # Step 5: Combine all analysis results
        if state_analysis:
            comprehensive_metrics['state_analysis'] = state_analysis
        
        # Step 6: Generate outputs
        output_files = {}
        for format_type in output_formats:
            if format_type == 'csv':
                output_path = f"{output_dir}/enhanced_messages.csv"
                output_files[format_type] = self.output_formatter.format_output(
                    enhanced_messages, format_type, output_path
                )
            else:
                output_path = f"{output_dir}/analysis_report.{format_type}"
                output_files[format_type] = self.output_formatter.format_output(
                    enhanced_messages, format_type, output_path, comprehensive_metrics, input_file
                )
        
        # Step 7: Generate sequence diagram if requested
        if generate_sequence_diagram:
            # For now, generate for all messages as one session (can be improved to per-session)
            mermaid_code = self.sequence_diagram_generator.generate_mermaid(enhanced_messages)
            seq_path = os.path.join(output_dir, "sequence_diagram.html")
            self.sequence_diagram_generator.save_mermaid_html(mermaid_code, seq_path)
            output_files['sequence_diagram'] = seq_path
        
        # Step 8: Generate timeline visualization if requested
        if generate_timeline:
            timeline_path = os.path.join(output_dir, "timeline.html")
            self.timeline_visualizer.create_timeline(enhanced_messages, timeline_path)
            output_files['timeline'] = timeline_path
            
            # Also generate detailed timeline
            detailed_timeline_path = os.path.join(output_dir, "detailed_timeline.html")
            self.timeline_visualizer.create_detailed_timeline(enhanced_messages, detailed_timeline_path)
            output_files['detailed_timeline'] = detailed_timeline_path
        
        logger.info(f"Analysis complete. Generated {len(output_files)} output files")
        return output_files 