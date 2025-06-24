"""LogLens reporting service for generating prioritized security analysis reports."""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import Counter
import math

from pydantic import BaseModel, Field

from ..models import Finding, DetectionResult


class ReportFormat(str, Enum):
    """Report output formats."""
    
    CONSOLE = "console"
    FILE = "file"


class RiskLevel(str, Enum):
    """Risk level categorization."""
    
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class OutputConfig(BaseModel):
    """Configuration for report output."""
    
    format: ReportFormat = ReportFormat.CONSOLE
    file_path: Optional[Path] = None
    max_findings: int = Field(default=5, description="Maximum findings to display in default mode")
    max_findings_verbose: int = Field(default=10, description="Maximum findings to display in verbose mode")
    include_executive_summary: bool = True
    include_recommendations: bool = True
    terminal_width: int = Field(default=79, description="Terminal width for formatting")


class ExecutiveSummary(BaseModel):
    """Executive summary of the security analysis."""
    
    analysis_period: Tuple[datetime, datetime]
    total_entries_processed: int
    total_findings: int
    critical_high_findings: int
    top_threats: List[Tuple[str, int]]  # (threat_type, count)
    processing_time: float
    detection_methods: List[str]
    recommendations: List[str]


class RiskCalculator:
    """Advanced risk scoring combining multiple factors."""
    
    def __init__(self):
        self.base_weights = {
            'detection_risk': 1.0,
            'ip_reputation': 0.4,
            'frequency_severity': 0.3,
            'geographic_risk': 0.2
        }
        
        self.risk_thresholds = {
            RiskLevel.CRITICAL: 90,
            RiskLevel.HIGH: 70,
            RiskLevel.MEDIUM: 40,
            RiskLevel.LOW: 0
        }
    
    def calculate_composite_risk(self, finding: Finding) -> int:
        """Calculate composite risk score from all available factors."""
        base_risk = finding.risk_score
        
        # IP reputation factor
        ip_risk_bonus = self._calculate_ip_reputation_bonus(finding)
        
        # Frequency pattern severity
        frequency_bonus = self._calculate_frequency_bonus(finding)
        
        # Geographic risk factor
        geo_bonus = self._calculate_geographic_bonus(finding)
        
        # Calculate weighted composite score
        composite_score = (
            base_risk +
            (ip_risk_bonus * self.base_weights['ip_reputation'] * 100) +
            (frequency_bonus * self.base_weights['frequency_severity'] * 100) +
            (geo_bonus * self.base_weights['geographic_risk'] * 100)
        )
        
        # Cap at 100
        return min(int(composite_score), 100)
    
    def _calculate_ip_reputation_bonus(self, finding: Finding) -> float:
        """Calculate IP reputation risk bonus (0.0-1.0)."""
        if not finding.enrichment_data or "ip_reputation" not in finding.enrichment_data:
            return 0.0
        
        ip_rep = finding.enrichment_data["ip_reputation"]
        ip_str = str(finding.log_entry.ip_address)
        
        if ip_str not in ip_rep:
            return 0.0
        
        max_bonus = 0.0
        for provider_data in ip_rep[ip_str].values():
            if provider_data.get("is_malicious", False):
                confidence = provider_data.get("confidence_score", 50) / 100.0
                max_bonus = max(max_bonus, confidence * 0.4)  # Up to 40% bonus
        
        return max_bonus
    
    def _calculate_frequency_bonus(self, finding: Finding) -> float:
        """Calculate frequency pattern severity bonus (0.0-1.0)."""
        if not finding.enrichment_data:
            return 0.0
        
        pattern_type = finding.enrichment_data.get("pattern_type", "")
        
        # High severity patterns
        if any(pattern in pattern_type.lower() for pattern in 
               ["brute_force", "dos_burst", "scanning", "behavioral_anomaly"]):
            return 0.3  # 30% bonus
        
        # Medium severity patterns
        if any(pattern in pattern_type.lower() for pattern in 
               ["frequency", "time_windowed", "geographic"]):
            return 0.2  # 20% bonus
        
        return 0.1  # Default frequency bonus
    
    def _calculate_geographic_bonus(self, finding: Finding) -> float:
        """Calculate geographic risk bonus (0.0-1.0)."""
        if not finding.enrichment_data or "ip_reputation" not in finding.enrichment_data:
            return 0.0
        
        ip_rep = finding.enrichment_data["ip_reputation"]
        ip_str = str(finding.log_entry.ip_address)
        
        if ip_str not in ip_rep:
            return 0.0
        
        high_risk_countries = {
            "CN": 0.1,  # China
            "RU": 0.15, # Russia
            "KP": 0.2,  # North Korea
            "IR": 0.15, # Iran
        }
        
        for provider_data in ip_rep[ip_str].values():
            country_code = provider_data.get("country_code", "")
            if country_code in high_risk_countries:
                return high_risk_countries[country_code]
        
        return 0.0
    
    def get_risk_level(self, risk_score: int) -> RiskLevel:
        """Get risk level category from numeric score."""
        if risk_score >= self.risk_thresholds[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif risk_score >= self.risk_thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif risk_score >= self.risk_thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW


class FindingFormatter:
    """Formats individual findings for display."""
    
    def __init__(self, terminal_width: int = 79):
        self.terminal_width = terminal_width
        
    def format_finding(self, finding: Finding, composite_risk: int, 
                      risk_level: RiskLevel, verbose: bool = False) -> str:
        """Format a single finding for display."""
        risk_emoji = {
            RiskLevel.CRITICAL: "🔴",
            RiskLevel.HIGH: "🟠", 
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.LOW: "🟢"
        }
        
        lines = []
        
        # Header with risk level and score
        header = f"{risk_emoji[risk_level]} {risk_level.value.upper()}: {finding.finding_type} (Risk Score: {composite_risk})"
        lines.append(header)
        
        # Description
        lines.append(f"    Description: {finding.description}")
        
        # IP and basic info
        lines.append(f"    IP Address: {finding.log_entry.ip_address}")
        lines.append(f"    Timestamp: {finding.log_entry.timestamp}")
        
        # IP reputation data
        rep_info = self._format_reputation_data(finding)
        if rep_info:
            lines.extend(rep_info)
        
        # Pattern details
        pattern_info = self._format_pattern_details(finding)
        if pattern_info:
            lines.extend(pattern_info)
        
        # Geographic context
        geo_info = self._format_geographic_context(finding)
        if geo_info:
            lines.extend(geo_info)
        
        # Verbose details
        if verbose:
            verbose_info = self._format_verbose_details(finding)
            lines.extend(verbose_info)
        
        return "\n".join(lines)
    
    def _format_reputation_data(self, finding: Finding) -> List[str]:
        """Format IP reputation information."""
        if not finding.enrichment_data or "ip_reputation" not in finding.enrichment_data:
            return []
        
        ip_rep = finding.enrichment_data["ip_reputation"]
        ip_str = str(finding.log_entry.ip_address)
        
        if ip_str not in ip_rep:
            return []
        
        lines = []
        rep_info = []
        
        for provider, data in ip_rep[ip_str].items():
            if data.get("is_malicious"):
                confidence = data.get("confidence_score", 0)
                rep_info.append(f"{provider.title()}: MALICIOUS ({confidence}% confidence)")
            elif data.get("confidence_score", 0) > 0:
                confidence = data.get("confidence_score", 0)
                rep_info.append(f"{provider.title()}: {confidence}% confidence")
        
        if rep_info:
            lines.append(f"    🛡️  Reputation: {', '.join(rep_info)}")
        
        return lines
    
    def _format_pattern_details(self, finding: Finding) -> List[str]:
        """Format frequency/behavioral pattern details."""
        if not finding.enrichment_data:
            return []
        
        lines = []
        pattern_type = finding.enrichment_data.get("pattern_type", "")
        
        if pattern_type:
            pattern_display = pattern_type.replace("_", " ").title()
            
            # Add time window info if available
            time_window = finding.enrichment_data.get("time_window", "")
            if time_window:
                lines.append(f"    ⏰ Pattern: {pattern_display} (Window: {time_window})")
            else:
                lines.append(f"    ⏰ Pattern: {pattern_display}")
        
        return lines
    
    def _format_geographic_context(self, finding: Finding) -> List[str]:
        """Format geographic location context."""
        if not finding.enrichment_data or "ip_reputation" not in finding.enrichment_data:
            return []
        
        ip_rep = finding.enrichment_data["ip_reputation"]
        ip_str = str(finding.log_entry.ip_address)
        
        if ip_str not in ip_rep:
            return []
        
        lines = []
        geo_info = []
        
        for provider_data in ip_rep[ip_str].values():
            country = provider_data.get("country", "")
            isp = provider_data.get("isp", "")
            
            if country or isp:
                geo_parts = []
                if country:
                    geo_parts.append(country)
                if isp:
                    geo_parts.append(isp)
                geo_info.append(" | ".join(geo_parts))
                break  # Use first available geographic info
        
        if geo_info:
            lines.append(f"    🌍 Location: {geo_info[0]}")
        
        return lines
    
    def _format_verbose_details(self, finding: Finding) -> List[str]:
        """Format additional verbose details."""
        lines = []
        
        # Request details
        lines.append(f"    📝 Request: {finding.log_entry.request_line}")
        lines.append(f"        Status: {finding.log_entry.status_code}")
        
        if finding.log_entry.user_agent:
            ua_display = finding.log_entry.user_agent[:60] + "..." if len(finding.log_entry.user_agent) > 60 else finding.log_entry.user_agent
            lines.append(f"        User-Agent: {ua_display}")
        
        if finding.log_entry.bytes_sent:
            lines.append(f"        Bytes Sent: {finding.log_entry.bytes_sent:,}")
        
        return lines


class ReportingService:
    """Main reporting service for generating security analysis reports."""
    
    def __init__(self, config: Optional[OutputConfig] = None):
        self.config = config or OutputConfig()
        self.risk_calculator = RiskCalculator()
        self.formatter = FindingFormatter(self.config.terminal_width)
    
    def generate_report(self, detection_result: DetectionResult, 
                       verbose: bool = False) -> str:
        """Generate a complete security analysis report."""
        if not detection_result.findings:
            return self._generate_empty_report(detection_result)
        
        # Calculate composite risk scores and sort findings
        enhanced_findings = self._enhance_findings_with_risk(detection_result.findings)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            detection_result, enhanced_findings
        )
        
        # Generate report sections
        report_sections = []
        
        # Header
        report_sections.append(self._generate_header())
        
        # Executive summary
        if self.config.include_executive_summary:
            report_sections.append(self._format_executive_summary(executive_summary))
        
        # Priority findings
        findings_limit = (self.config.max_findings_verbose if verbose 
                         else self.config.max_findings)
        report_sections.append(self._format_priority_findings(
            enhanced_findings[:findings_limit], verbose
        ))
        
        # Analysis summary footer
        report_sections.append(self._format_analysis_summary(
            detection_result, executive_summary
        ))
        
        return "\n\n".join(report_sections)
    
    def save_report(self, report_content: str, file_path: Path) -> None:
        """Save report content to file."""
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
        except Exception as e:
            raise RuntimeError(f"Failed to save report to {file_path}: {str(e)}")
    
    def _enhance_findings_with_risk(self, findings: List[Finding]) -> List[Tuple[Finding, int, RiskLevel]]:
        """Enhance findings with composite risk scores and sort by priority."""
        enhanced = []
        
        for finding in findings:
            composite_risk = self.risk_calculator.calculate_composite_risk(finding)
            risk_level = self.risk_calculator.get_risk_level(composite_risk)
            enhanced.append((finding, composite_risk, risk_level))
        
        # Sort by composite risk score (highest first)
        enhanced.sort(key=lambda x: x[1], reverse=True)
        
        return enhanced
    
    def _generate_executive_summary(self, detection_result: DetectionResult,
                                  enhanced_findings: List[Tuple[Finding, int, RiskLevel]]) -> ExecutiveSummary:
        """Generate executive summary from detection results."""
        # Calculate time range
        timestamps = [f[0].log_entry.timestamp for f in enhanced_findings]
        time_range = (min(timestamps), max(timestamps)) if timestamps else (datetime.now(), datetime.now())
        
        # Count critical/high risk findings
        critical_high_count = sum(1 for _, _, risk_level in enhanced_findings 
                                if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH])
        
        # Top threats analysis
        threat_counter = Counter()
        for finding, _, _ in enhanced_findings:
            threat_counter[finding.finding_type] += 1
        
        top_threats = threat_counter.most_common(3)
        
        # Detection methods used (inferred from finding types)
        detection_methods = list(set(f[0].finding_type for f in enhanced_findings))
        
        # Generate recommendations
        recommendations = self._generate_recommendations(enhanced_findings)
        
        return ExecutiveSummary(
            analysis_period=time_range,
            total_entries_processed=detection_result.total_entries_analyzed,
            total_findings=detection_result.total_findings,
            critical_high_findings=critical_high_count,
            top_threats=top_threats,
            processing_time=detection_result.processing_time_seconds or 0.0,
            detection_methods=detection_methods,
            recommendations=recommendations
        )
    
    def _generate_recommendations(self, enhanced_findings: List[Tuple[Finding, int, RiskLevel]]) -> List[str]:
        """Generate context-based security recommendations."""
        recommendations = []
        
        if not enhanced_findings:
            return ["No security threats detected. Continue monitoring."]
        
        # Check for critical/high risk findings
        high_risk_count = sum(1 for _, _, risk_level in enhanced_findings
                            if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH])
        
        if high_risk_count > 0:
            recommendations.append(f"🚨 URGENT: {high_risk_count} critical/high-risk threats require immediate attention")
        
        # Check for specific threat patterns
        threat_types = set(f[0].finding_type for f in enhanced_findings)
        
        if any("Brute Force" in t for t in threat_types):
            recommendations.append("🔒 Implement rate limiting and account lockout policies")
        
        if any("Scanning" in t for t in threat_types):
            recommendations.append("🛡️  Deploy web application firewall (WAF) to block scanning attempts")
        
        if any("SQL" in t for t in threat_types):
            recommendations.append("💉 Review application code for SQL injection vulnerabilities")
        
        # IP reputation findings
        malicious_ips = sum(1 for f, _, _ in enhanced_findings
                           if f.enrichment_data and 
                           any(data.get("is_malicious", False) 
                               for provider_data in f.enrichment_data.get("ip_reputation", {}).values()
                               for data in provider_data.values() if isinstance(data, dict)))
        
        if malicious_ips > 0:
            recommendations.append(f"⛔ Block {malicious_ips} known malicious IP addresses at firewall level")
        
        return recommendations
    
    def _generate_header(self) -> str:
        """Generate report header."""
        separator = "═" * self.config.terminal_width
        title = "LOGLENS SECURITY ANALYSIS REPORT"
        title_padding = (self.config.terminal_width - len(title)) // 2
        
        return f"{separator}\n{' ' * title_padding}{title}\n{separator}"
    
    def _format_executive_summary(self, summary: ExecutiveSummary) -> str:
        """Format executive summary section."""
        lines = ["Executive Summary:"]
        
        start_time = summary.analysis_period[0].strftime("%Y-%m-%d %H:%M:%S")
        end_time = summary.analysis_period[1].strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"  📊 Analysis Period: {start_time} - {end_time}")
        lines.append(f"  📈 Log Entries Processed: {summary.total_entries_processed:,}")
        lines.append(f"  🚨 Total Security Findings: {summary.total_findings:,}")
        lines.append(f"  🔴 Critical/High Risk Issues: {summary.critical_high_findings}")
        
        if summary.top_threats:
            lines.append("\nTop Threats Identified:")
            for threat_type, count in summary.top_threats:
                lines.append(f"  • {threat_type} ({count} instances)")
        
        return "\n".join(lines)
    
    def _format_priority_findings(self, enhanced_findings: List[Tuple[Finding, int, RiskLevel]], 
                                verbose: bool) -> str:
        """Format priority findings section."""
        separator = "═" * self.config.terminal_width
        section_title = "PRIORITY FINDINGS"
        title_padding = (self.config.terminal_width - len(section_title)) // 2
        
        lines = [f"{separator}\n{' ' * title_padding}{section_title}\n{separator}"]
        
        if not enhanced_findings:
            lines.append("No security findings detected.")
            return "\n".join(lines)
        
        for i, (finding, composite_risk, risk_level) in enumerate(enhanced_findings):
            finding_text = self.formatter.format_finding(
                finding, composite_risk, risk_level, verbose
            )
            lines.append(finding_text)
            
            # Add separator between findings (except last)
            if i < len(enhanced_findings) - 1:
                lines.append("")
        
        return "\n".join(lines)
    
    def _format_analysis_summary(self, detection_result: DetectionResult,
                               executive_summary: ExecutiveSummary) -> str:
        """Format analysis summary footer."""
        separator = "═" * self.config.terminal_width
        section_title = "ANALYSIS SUMMARY"
        title_padding = (self.config.terminal_width - len(section_title)) // 2
        
        lines = [f"{separator}\n{' ' * title_padding}{section_title}\n{separator}"]
        
        # Detection methods
        methods = ", ".join(executive_summary.detection_methods)
        lines.append(f"Detection Methods Used: {methods}")
        
        # Processing time
        processing_time = executive_summary.processing_time
        lines.append(f"Processing Time: {processing_time:.3f} seconds")
        
        # Report timestamp
        lines.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Recommendations
        if self.config.include_recommendations and executive_summary.recommendations:
            lines.append("\n🔍 Recommendations:")
            for rec in executive_summary.recommendations:
                lines.append(f"   {rec}")
        
        return "\n".join(lines)
    
    def _generate_empty_report(self, detection_result: DetectionResult) -> str:
        """Generate report when no findings are detected."""
        lines = []
        lines.append(self._generate_header())
        lines.append("\n✅ CLEAN LOG ANALYSIS")
        lines.append(f"\n📊 Log Entries Processed: {detection_result.total_entries_analyzed:,}")
        lines.append("🚨 Security Findings: 0")
        lines.append("\n🎉 No security threats detected in the analyzed log data.")
        lines.append("Continue monitoring for emerging threats.")
        
        processing_time = detection_result.processing_time_seconds or 0.0
        lines.append(f"\n🕒 Processing Time: {processing_time:.3f} seconds")
        lines.append(f"📅 Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        return "\n".join(lines) 