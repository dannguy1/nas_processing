"""
Container Analysis Visualizer
Provides visualization tools for NAS container analysis results
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import numpy as np
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class ContainerVisualizer:
    """Visualization tools for container analysis results"""
    
    def __init__(self, output_dir: str = "data/visualizations"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up plotting style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
    def create_container_summary_chart(self, analysis_data: Dict[str, Any], 
                                     filename: str = "container_summary.png") -> str:
        """Create a comprehensive container summary chart"""
        
        summary = analysis_data.get('container_analysis', {}).get('summary', {})
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('NAS Container Analysis Summary', fontsize=16, fontweight='bold')
        
        # 1. Container Coverage Pie Chart
        total_msgs = summary.get('total_messages', 0)
        msgs_with_containers = summary.get('messages_with_containers', 0)
        msgs_without_containers = total_msgs - msgs_with_containers
        
        labels = ['With Containers', 'Without Containers']
        sizes = [msgs_with_containers, msgs_without_containers]
        colors = ['#2E8B57', '#FF6B6B']
        
        ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax1.set_title('Container Coverage')
        
        # 2. Container Types Bar Chart
        container_types = summary.get('container_types', {})
        if container_types:
            types = list(container_types.keys())
            counts = list(container_types.values())
            
            bars = ax2.bar(range(len(types)), counts, color='#4ECDC4')
            ax2.set_title('Container Types Distribution')
            ax2.set_xlabel('Container Type')
            ax2.set_ylabel('Count')
            ax2.set_xticks(range(len(types)))
            ax2.set_xticklabels(types, rotation=45, ha='right')
            
            # Add value labels on bars
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                        f'{count}', ha='center', va='bottom')
        
        # 3. Protocol Distribution
        protocol_dist = summary.get('protocol_distribution', {})
        if protocol_dist:
            protocols = list(protocol_dist.keys())[:10]  # Top 10
            counts = list(protocol_dist.values())[:10]
            
            bars = ax3.barh(range(len(protocols)), counts, color='#45B7D1')
            ax3.set_title('Top Protocol Types')
            ax3.set_xlabel('Count')
            ax3.set_yticks(range(len(protocols)))
            ax3.set_yticklabels(protocols)
            
            # Add value labels
            for i, count in enumerate(counts):
                ax3.text(count + 0.1, i, f'{count}', va='center')
        
        # 4. Vendor Container Stats
        vendor_stats = summary.get('vendor_container_stats', {})
        if vendor_stats:
            vendors = list(vendor_stats.keys())
            counts = list(vendor_stats.values())
            
            bars = ax4.bar(range(len(vendors)), counts, color='#96CEB4')
            ax4.set_title('Vendor-Specific Containers')
            ax4.set_xlabel('Vendor ID')
            ax4.set_ylabel('Count')
            ax4.set_xticks(range(len(vendors)))
            ax4.set_xticklabels(vendors)
            
            # Add value labels
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                        f'{count}', ha='center', va='bottom')
        
        plt.tight_layout()
        output_path = self.output_dir / filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(output_path)
    
    def create_timeline_chart(self, csv_data: pd.DataFrame, 
                            filename: str = "container_timeline.png") -> str:
        """Create a timeline chart showing container activity over time"""
        
        # Convert timestamp to datetime
        csv_data['datetime'] = pd.to_datetime(csv_data['timestamp'], 
                                            format='%Y %b %d %H:%M:%S.%f')
        
        # Filter messages with actual containers
        container_msgs = csv_data[csv_data['has_embedded_containers'] == True]
        
        if container_msgs.empty:
            logger.warning("No container messages found for timeline")
            return ""
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10))
        fig.suptitle('Container Activity Timeline', fontsize=16, fontweight='bold')
        
        # 1. Container Activity Over Time
        container_msgs['hour_minute'] = container_msgs['datetime'].dt.strftime('%H:%M')
        activity_counts = container_msgs.groupby('hour_minute').size()
        
        ax1.plot(activity_counts.index, activity_counts.values, 
                marker='o', linewidth=2, markersize=6, color='#2E8B57')
        ax1.set_title('Container Messages Over Time')
        ax1.set_xlabel('Time (HH:MM)')
        ax1.set_ylabel('Number of Messages')
        ax1.grid(True, alpha=0.3)
        
        # Rotate x-axis labels for better readability
        ax1.tick_params(axis='x', rotation=45)
        
        # 2. Message Types with Containers
        msg_type_counts = container_msgs['message_type'].value_counts()
        
        bars = ax2.bar(range(len(msg_type_counts)), msg_type_counts.values, 
                      color='#4ECDC4')
        ax2.set_title('Message Types with Containers')
        ax2.set_xlabel('Message Type')
        ax2.set_ylabel('Count')
        ax2.set_xticks(range(len(msg_type_counts)))
        ax2.set_xticklabels(msg_type_counts.index, rotation=45, ha='right')
        
        # Add value labels
        for bar, count in zip(bars, msg_type_counts.values):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{count}', ha='center', va='bottom')
        
        plt.tight_layout()
        output_path = self.output_dir / filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(output_path)
    
    def create_bearer_analysis_chart(self, csv_data: pd.DataFrame,
                                   filename: str = "bearer_analysis.png") -> str:
        """Create bearer-specific analysis charts"""
        
        # Filter bearer-related messages
        bearer_msgs = csv_data[csv_data['bearer_id'].notna()]
        
        if bearer_msgs.empty:
            logger.warning("No bearer messages found")
            return ""
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Bearer Context Analysis', fontsize=16, fontweight='bold')
        
        # 1. Bearer ID Distribution
        bearer_counts = bearer_msgs['bearer_id'].value_counts()
        ax1.pie(bearer_counts.values, labels=bearer_counts.index, autopct='%1.1f%%')
        ax1.set_title('Bearer ID Distribution')
        
        # 2. Bearer State Transitions
        state_counts = bearer_msgs['bearer_state'].value_counts()
        bars = ax2.bar(range(len(state_counts)), state_counts.values, color='#45B7D1')
        ax2.set_title('Bearer States')
        ax2.set_xlabel('State')
        ax2.set_ylabel('Count')
        ax2.set_xticks(range(len(state_counts)))
        ax2.set_xticklabels(state_counts.index, rotation=45, ha='right')
        
        # 3. QCI Distribution
        qci_counts = bearer_msgs['qci'].value_counts()
        if not qci_counts.empty:
            bars = ax3.bar(range(len(qci_counts)), qci_counts.values, color='#96CEB4')
            ax3.set_title('QCI Distribution')
            ax3.set_xlabel('QCI Value')
            ax3.set_ylabel('Count')
            ax3.set_xticks(range(len(qci_counts)))
            ax3.set_xticklabels(qci_counts.index)
        
        # 4. Connection ID Analysis
        conn_counts = bearer_msgs['connection_id'].value_counts()
        if not conn_counts.empty:
            bars = ax4.bar(range(len(conn_counts)), conn_counts.values, color='#FF6B6B')
            ax4.set_title('Connection ID Distribution')
            ax4.set_xlabel('Connection ID')
            ax4.set_ylabel('Count')
            ax4.set_xticks(range(len(conn_counts)))
            ax4.set_xticklabels(conn_counts.index)
        
        plt.tight_layout()
        output_path = self.output_dir / filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(output_path)
    
    def create_protocol_analysis_chart(self, analysis_data: Dict[str, Any],
                                     filename: str = "protocol_analysis.png") -> str:
        """Create protocol-specific analysis charts"""
        
        protocol_dist = analysis_data.get('container_analysis', {}).get('summary', {}).get('protocol_distribution', {})
        
        if not protocol_dist:
            logger.warning("No protocol distribution data found")
            return ""
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        fig.suptitle('Protocol Analysis', fontsize=16, fontweight='bold')
        
        # 1. Protocol Distribution (Top 15)
        sorted_protocols = sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True)[:15]
        protocols, counts = zip(*sorted_protocols)
        
        bars = ax1.barh(range(len(protocols)), counts, color='#4ECDC4')
        ax1.set_title('Top 15 Protocol Types')
        ax1.set_xlabel('Count')
        ax1.set_yticks(range(len(protocols)))
        ax1.set_yticklabels(protocols)
        
        # Add value labels
        for i, count in enumerate(counts):
            ax1.text(count + 0.1, i, f'{count}', va='center')
        
        # 2. Protocol Categories
        # Group protocols by type
        dns_protocols = {k: v for k, v in protocol_dist.items() if 'DNS' in k}
        ip_protocols = {k: v for k, v in protocol_dist.items() if 'IP' in k or 'MTU' in k}
        other_protocols = {k: v for k, v in protocol_dist.items() 
                          if 'DNS' not in k and 'IP' not in k and 'MTU' not in k}
        
        categories = ['DNS Protocols', 'IP/MTU Protocols', 'Other Protocols']
        category_counts = [sum(dns_protocols.values()), 
                         sum(ip_protocols.values()), 
                         sum(other_protocols.values())]
        
        colors = ['#2E8B57', '#45B7D1', '#FF6B6B']
        ax2.pie(category_counts, labels=categories, colors=colors, autopct='%1.1f%%')
        ax2.set_title('Protocol Categories')
        
        plt.tight_layout()
        output_path = self.output_dir / filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(output_path)
    
    def create_detailed_container_report(self, analysis_data: Dict[str, Any],
                                       csv_data: pd.DataFrame,
                                       filename: str = "detailed_container_report.html") -> str:
        """Create a detailed HTML report with all container analysis results"""
        
        summary = analysis_data.get('container_analysis', {}).get('summary', {})
        details = analysis_data.get('container_analysis', {}).get('details', {})
        
        # Create container detail pages directory
        container_pages_dir = self.output_dir / "container_details"
        container_pages_dir.mkdir(exist_ok=True)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NAS Container Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2E8B57; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #f5f5f5; border-radius: 3px; }}
                .container-type {{ margin: 10px 0; padding: 10px; background-color: #e8f5e8; border-left: 4px solid #2E8B57; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .highlight {{ background-color: #fff3cd; }}
                .container-link {{ color: #2E8B57; text-decoration: none; font-weight: bold; }}
                .container-link:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 NAS Container Analysis Report</h1>
                <p>Comprehensive analysis of embedded containers in LTE NAS messages</p>
            </div>
            
            <div class="section">
                <h2>📈 Summary Statistics</h2>
                <div class="metric">
                    <strong>Total Messages:</strong> {summary.get('total_messages', 0)}
                </div>
                <div class="metric">
                    <strong>Messages with Containers:</strong> {summary.get('messages_with_containers', 0)}
                </div>
                <div class="metric">
                    <strong>Container Coverage:</strong> {summary.get('container_coverage_percentage', 0):.1f}%
                </div>
            </div>
            
            <div class="section">
                <h2>🔍 Container Types Analysis</h2>
        """
        
        # Add container types
        container_types = summary.get('container_types', {})
        for container_type, count in container_types.items():
            html_content += f"""
                <div class="container-type">
                    <h3>{container_type.replace('_', ' ').title()}</h3>
                    <p><strong>Count:</strong> {count}</p>
                </div>
            """
        
        # Add protocol distribution
        html_content += """
            </div>
            
            <div class="section">
                <h2>🌐 Protocol Distribution</h2>
                <table>
                    <tr><th>Protocol Type</th><th>Count</th></tr>
        """
        
        protocol_dist = summary.get('protocol_distribution', {})
        for protocol, count in sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True):
            html_content += f"<tr><td>{protocol}</td><td>{count}</td></tr>"
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h2>🏢 Vendor-Specific Containers</h2>
                <table>
                    <tr><th>Vendor ID</th><th>Count</th></tr>
        """
        
        vendor_stats = summary.get('vendor_container_stats', {})
        for vendor_id, count in vendor_stats.items():
            html_content += f"<tr><td>{vendor_id}</td><td>{count}</td></tr>"
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h2>📋 Message Details with Containers</h2>
                <table>
                    <tr><th>Timestamp</th><th>Message Type</th><th>Direction</th><th>Bearer ID</th><th>QCI</th><th>Container Details</th></tr>
        """
        
        # Add message details with links to individual container pages
        # Use actual container data: messages with embedded containers
        container_msgs = csv_data[csv_data['has_embedded_containers'] == True]
        for idx, row in container_msgs.head(20).iterrows():  # Show first 20
            container_json = row.get('embedded_containers_json', '')
            
            # Create individual container detail page
            if container_json and isinstance(container_json, str) and container_json.strip():
                # Create a unique filename for this message
                timestamp_clean = row.get('timestamp', '').replace(' ', '_').replace(':', '-')
                msg_type_clean = row.get('message_type', '').replace(' ', '_').replace('/', '_')
                detail_filename = f"container_detail_{timestamp_clean}_{msg_type_clean}.html"
                detail_path = container_pages_dir / detail_filename
                
                # Create the individual container detail page
                self._create_individual_container_page(detail_path, row, container_json)
                
                # Add link to the main report
                html_content += f"""
                <tr>
                    <td>{row.get('timestamp', '')}</td>
                    <td>{row.get('message_type', '')}</td>
                    <td>{row.get('direction', '')}</td>
                    <td>{row.get('bearer_id', '')}</td>
                    <td>{row.get('qci', '')}</td>
                    <td>
                        <a href="container_details/{detail_filename}" class="container-link" target="_blank">
                            📋 View Container Details
                        </a>
                    </td>
                </tr>
                """
            else:
                html_content += f"""
                <tr>
                    <td>{row.get('timestamp', '')}</td>
                    <td>{row.get('message_type', '')}</td>
                    <td>{row.get('direction', '')}</td>
                    <td>{row.get('bearer_id', '')}</td>
                    <td>{row.get('qci', '')}</td>
                    <td>No container content available</td>
                </tr>
                """
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h2>💡 Key Insights</h2>
                <ul>
                    <li><strong>Container Coverage:</strong> {:.1f}% of messages contain embedded containers</li>
                    <li><strong>Most Common Protocol:</strong> {}</li>
                    <li><strong>Primary Bearer ID:</strong> {}</li>
                    <li><strong>QCI Value:</strong> {}</li>
                </ul>
            </div>
        </body>
        </html>
        """.format(
            summary.get('container_coverage_percentage', 0),
            max(protocol_dist.items(), key=lambda x: x[1])[0] if protocol_dist else "N/A",
            summary.get('bearer_id_info', {}).get('bearer_id_value', 'N/A'),
            summary.get('qci_info', {}).get('qci_value', 'N/A')
        )
        
        output_path = self.output_dir / filename
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _create_individual_container_page(self, file_path: Path, row: pd.Series, container_json: str):
        """Create an individual container detail page for a specific message."""
        
        # Parse the JSON for better display
        try:
            import json
            container_data = json.loads(container_json)
            formatted_json = json.dumps(container_data, indent=2)
        except:
            formatted_json = container_json
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Container Details - {row.get('message_type', 'Unknown')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }}
                .header {{ background-color: #2E8B57; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .message-info {{ background-color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .container-content {{ background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
                .info-item {{ padding: 10px; background-color: #f8f9fa; border-radius: 3px; }}
                .info-label {{ font-weight: bold; color: #2E8B57; }}
                .json-content {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 12px; line-height: 1.4; }}
                .back-link {{ color: #2E8B57; text-decoration: none; font-weight: bold; }}
                .back-link:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📋 Container Details</h1>
                <p>Detailed container analysis for: <strong>{row.get('message_type', 'Unknown')}</strong></p>
                <a href="../detailed_container_report.html" class="back-link">← Back to Container Report</a>
            </div>
            
            <div class="message-info">
                <h2>📄 Message Information</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Timestamp:</div>
                        <div>{row.get('timestamp', 'N/A')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Message Type:</div>
                        <div>{row.get('message_type', 'N/A')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Direction:</div>
                        <div>{row.get('direction', 'N/A')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Bearer ID:</div>
                        <div>{row.get('bearer_id', 'N/A')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">QCI:</div>
                        <div>{row.get('qci', 'N/A')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Subscription ID:</div>
                        <div>{row.get('subscription_id', 'N/A')}</div>
                    </div>
                </div>
            </div>
            
            <div class="container-content">
                <h2>🔍 Embedded Container Content</h2>
                <div class="json-content">
                    <pre>{formatted_json}</pre>
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(file_path, 'w') as f:
            f.write(html_content)
    
    def generate_all_visualizations(self, analysis_data: Dict[str, Any], 
                                  csv_file: str) -> Dict[str, str]:
        """Generate all visualization charts and reports"""
        
        logger.info("Generating container analysis visualizations...")
        
        # Load CSV data
        csv_data = pd.read_csv(csv_file)
        
        results = {}
        
        try:
            # Generate all charts
            results['summary_chart'] = self.create_container_summary_chart(analysis_data)
            results['timeline_chart'] = self.create_timeline_chart(csv_data)
            results['bearer_analysis'] = self.create_bearer_analysis_chart(csv_data)
            results['protocol_analysis'] = self.create_protocol_analysis_chart(analysis_data)
            results['detailed_report'] = self.create_detailed_container_report(analysis_data, csv_data)
            
            logger.info(f"Generated {len(results)} visualization files")
            
        except Exception as e:
            logger.error(f"Error generating visualizations: {e}")
        
        return results 