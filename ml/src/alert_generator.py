#!/usr/bin/env python3

"""
Alert Generator for SSH Brute-Force Detection
Generates JSON alerts and statistics for detected attacks
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class AlertGenerator:
    """
    Generates JSON alerts and statistics for detected SSH brute-force attacks
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize alert generator

        Args:
            config: Configuration dictionary
        """
        self.config = config

        # Create output directories
        self.alerts_dir = Path(config['paths']['alerts'])
        self.stats_dir = Path(config['paths']['statistics'])
        self.alerts_dir.mkdir(parents=True, exist_ok=True)
        self.stats_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Alert Generator initialized")

    def generate_alert_json(self, attacker_ip: str, attacker_flows: List[Dict],
                            csv_sources: List[str], detection_timestamp: datetime) -> str:
        """
        Generate JSON alert file for detected attacker

        Args:
            attacker_ip: IP address of attacker
            attacker_flows: List of attack flow dictionaries
            csv_sources: List of source CSV filenames
            detection_timestamp: Timestamp of detection

        Returns:
            Path to generated alert file
        """
        # Calculate confidence breakdown
        confidence_breakdown = self._get_confidence_breakdown(attacker_flows)

        # Create alert data structure
        alert = {
            'alert_id': self._generate_alert_id(attacker_ip, detection_timestamp),
            'timestamp': detection_timestamp.isoformat(),
            'attacker_ip': attacker_ip,
            'attack_type': 'SSH_BRUTE_FORCE',
            'severity': self._calculate_severity(attacker_flows),
            'total_flows': len(attacker_flows),
            'confidence': {
                'average': round(confidence_breakdown['average'], 4),
                'min': round(confidence_breakdown['min'], 4),
                'max': round(confidence_breakdown['max'], 4),
                'breakdown': confidence_breakdown['breakdown']
            },
            'flows': self._format_flows(attacker_flows),
            'source_csvs': csv_sources,
            'targets': self._extract_targets(attacker_flows)
        }

        # Generate filename
        timestamp_str = detection_timestamp.strftime('%Y%m%d_%H%M%S')
        filename = f"alert_{attacker_ip.replace('.', '_')}_{timestamp_str}.json"
        filepath = self.alerts_dir / filename

        # Write alert to file
        try:
            with open(filepath, 'w') as f:
                json.dump(alert, f, indent=2)
            logger.info(f"Generated alert file: {filename}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Failed to write alert file {filename}: {e}")
            raise

    def generate_statistics_json(self, result, model_info: Dict) -> str:
        """
        Generate statistics JSON file for detection result
        Only called when attacks are detected

        Args:
            result: DetectionResult object
            model_info: Model information dictionary

        Returns:
            Path to generated statistics file
        """
        # Calculate confidence breakdown for all attacks
        confidence_breakdown = self._get_confidence_breakdown(result.attack_flows)

        # Create statistics data structure
        statistics = {
            'timestamp': result.timestamp.isoformat(),
            'csv_filename': result.csv_filename,
            'processing_time': round(result.processing_time, 3),
            'total_flows': result.total_flows,
            'attack_flows': len(result.attack_flows),
            'attack_percentage': round((len(result.attack_flows) / result.total_flows * 100),
                                       2) if result.total_flows > 0 else 0,
            'unique_attackers': len(result.attackers),
            'attackers': result.attackers,
            'confidence': {
                'average': round(confidence_breakdown['average'], 4),
                'min': round(confidence_breakdown['min'], 4),
                'max': round(confidence_breakdown['max'], 4),
                'breakdown': confidence_breakdown['breakdown']
            },
            'model': model_info
        }

        # Generate filename
        timestamp_str = result.timestamp.strftime('%Y%m%d_%H%M%S')
        csv_base = Path(result.csv_filename).stem
        filename = f"stats_{csv_base}_{timestamp_str}.json"
        filepath = self.stats_dir / filename

        # Write statistics to file
        try:
            with open(filepath, 'w') as f:
                json.dump(statistics, f, indent=2)
            logger.info(f"Generated statistics file: {filename}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Failed to write statistics file {filename}: {e}")
            raise

    def _generate_alert_id(self, attacker_ip: str, timestamp: datetime) -> str:
        """
        Generate unique alert ID

        Args:
            attacker_ip: Attacker IP address
            timestamp: Detection timestamp

        Returns:
            Alert ID string
        """
        timestamp_str = timestamp.strftime('%Y%m%d%H%M%S')
        ip_part = attacker_ip.replace('.', '')
        return f"SSH_BF_{ip_part}_{timestamp_str}"

    def _calculate_severity(self, flows: List[Dict]) -> str:
        """
        Calculate alert severity based on flow count

        Args:
            flows: List of attack flows

        Returns:
            Severity string: LOW, MEDIUM, HIGH, CRITICAL
        """
        flow_count = len(flows)

        if flow_count >= 100:
            return "CRITICAL"
        elif flow_count >= 50:
            return "HIGH"
        elif flow_count >= 10:
            return "MEDIUM"
        else:
            return "LOW"

    def _get_confidence_breakdown(self, flows: List[Dict]) -> Dict:
        """
        Calculate confidence score breakdown

        Args:
            flows: List of attack flows with probability scores

        Returns:
            Dictionary with confidence statistics and breakdown
        """
        if not flows:
            return {
                'average': 0.0,
                'min': 0.0,
                'max': 0.0,
                'breakdown': {}
            }

        probabilities = [flow['probability'] for flow in flows]

        # Calculate breakdown by confidence ranges
        breakdown = {
            '0.50-0.60': 0,
            '0.60-0.70': 0,
            '0.70-0.80': 0,
            '0.80-0.90': 0,
            '0.90-1.00': 0
        }

        for prob in probabilities:
            if 0.50 <= prob < 0.60:
                breakdown['0.50-0.60'] += 1
            elif 0.60 <= prob < 0.70:
                breakdown['0.60-0.70'] += 1
            elif 0.70 <= prob < 0.80:
                breakdown['0.70-0.80'] += 1
            elif 0.80 <= prob < 0.90:
                breakdown['0.80-0.90'] += 1
            elif 0.90 <= prob <= 1.00:
                breakdown['0.90-1.00'] += 1

        return {
            'average': sum(probabilities) / len(probabilities),
            'min': min(probabilities),
            'max': max(probabilities),
            'breakdown': breakdown
        }

    def _format_flows(self, flows: List[Dict]) -> List[Dict]:
        """
        Format flow data for alert output

        Args:
            flows: List of attack flow dictionaries

        Returns:
            List of formatted flow dictionaries
        """
        formatted = []

        for flow in flows:
            formatted.append({
                'flow_index': flow['flow_index'],
                'probability': round(flow['probability'], 4),
                'src_ip': flow['flow_data']['src_ip'],
                'dst_ip': flow['flow_data']['dst_ip'],
                'src_port': flow['flow_data']['src_port'],
                'dst_port': flow['flow_data']['dst_port'],
                'protocol': flow['flow_data']['protocol'],
                'timestamp': flow['flow_data']['timestamp'],
                'flow_duration': flow['flow_data']['flow_duration']
            })

        return formatted

    def _extract_targets(self, flows: List[Dict]) -> List[Dict]:
        """
        Extract unique target IPs and ports from flows

        Args:
            flows: List of attack flow dictionaries

        Returns:
            List of unique target dictionaries
        """
        targets = {}

        for flow in flows:
            dst_ip = flow['flow_data']['dst_ip']
            dst_port = flow['flow_data']['dst_port']

            key = f"{dst_ip}:{dst_port}"
            if key not in targets:
                targets[key] = {
                    'ip': dst_ip,
                    'port': dst_port,
                    'flow_count': 0
                }
            targets[key]['flow_count'] += 1

        return list(targets.values())
