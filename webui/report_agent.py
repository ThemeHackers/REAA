import os
import json
import logging
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from core.config import settings
from core.llm_client import LLMClient

log = structlog.get_logger()


class ReportAgent:
    """Generate comprehensive security reports from analysis results"""

    def __init__(self):
        self.llm_client = self._init_llm_client()
        self.report_templates = self._load_templates()

    def _init_llm_client(self) -> Optional[LLMClient]:
        """Initialize LLM client for report generation"""
        try:
            return LLMClient(
                model=settings.ANGR_LLM_MODEL,
                api_base=settings.ANGR_LLM_API_BASE,
                api_key=settings.ANGR_LLM_API_KEY
            )
        except Exception as e:
            log.error(f"Failed to initialize LLM client: {e}", exc_info=True)
            return None

    def _load_templates(self) -> Dict[str, str]:
        """Load report templates"""
        return {
            "executive_summary": """
EXECUTIVE SUMMARY
================
Binary: {binary_path}
Analysis Date: {analysis_date}
Analysis Duration: {duration} seconds

OVERVIEW
--------
{overview}

KEY FINDINGS
------------
{key_findings}

RISK ASSESSMENT
----------------
Risk Score: {risk_score}/10
Risk Level: {risk_level}

RECOMMENDATIONS
---------------
{recommendations}
""",
            "technical_details": """
TECHNICAL ANALYSIS REPORT
=========================
Binary: {binary_path}
Analysis Date: {analysis_date}

STATIC ANALYSIS
---------------
{static_analysis}

DYNAMIC ANALYSIS
----------------
{dynamic_analysis}

SECURITY ANALYSIS
-----------------
{security_analysis}

VULNERABILITIES
---------------
{vulnerabilities}

MALWARE BEHAVIORS
-----------------
{malware_behaviors}
""",
            "cvss_report": """
CVSS SCORING REPORT
==================
Binary: {binary_path}
Analysis Date: {analysis_date}

BASE METRICS
-----------
Attack Vector (AV): {av}
Attack Complexity (AC): {ac}
Privileges Required (PR): {pr}
User Interaction (UI): {ui}
Scope (S): {s}
Confidentiality (C): {c}
Integrity (I): {i}
Availability (A): {a}

BASE SCORE: {base_score}

TEMPORAL METRICS
----------------
Exploit Code Maturity (E): {e}
Remediation Level (RL): {rl}
Report Confidence (RC): {rc}

TEMPORAL SCORE: {temporal_score}
"""
        }

    def generate_comprehensive_report(
        self,
        job_id: str,
        analysis_results: Dict[str, Any],
        output_format: str = "json"
    ) -> Optional[Dict[str, Any]]:
        """Generate a comprehensive security report"""
        try:
            report = {
                "job_id": job_id,
                "binary_path": analysis_results.get("binary_path", "unknown"),
                "generated_at": datetime.utcnow().isoformat(),
                "executive_summary": self._generate_executive_summary(analysis_results),
                "technical_details": self._generate_technical_details(analysis_results),
                "cvss_score": self._calculate_cvss_score(analysis_results),
                "risk_assessment": self._perform_risk_assessment(analysis_results),
                "recommendations": self._generate_recommendations(analysis_results)
            }

            if output_format == "html":
                report["html"] = self._convert_to_html(report)
            elif output_format == "pdf":
                report["pdf_path"] = self._convert_to_pdf(report, job_id)

            return report

        except Exception as e:
            log.error(f"Failed to generate report for job {job_id}: {e}", exc_info=True)
            return None

    def _generate_executive_summary(self, analysis_results: Dict[str, Any]) -> str:
        """Generate executive summary of analysis"""
        try:
            binary_path = analysis_results.get("binary_path", "unknown")
            duration = analysis_results.get("duration", 0)

            overview = f"Security analysis of {binary_path} completed in {duration} seconds."

            key_findings = []
            results = analysis_results.get("results", {})

            if "static" in results:
                key_findings.append(f"Static analysis identified {len(results.get('static', {}).get('functions', []))} functions")

            if "security" in results:
                vulnerabilities = results.get("security", {}).get("vulnerabilities", [])
                key_findings.append(f"Security analysis found {len(vulnerabilities)} potential vulnerabilities")

            if "dynamic" in results:
                key_findings.append("Dynamic analysis performed with runtime monitoring")

            risk_score = self._calculate_risk_score(analysis_results)
            risk_level = self._get_risk_level(risk_score)

            recommendations = self._get_high_level_recommendations(analysis_results)

            template = self.report_templates["executive_summary"]
            summary = template.format(
                binary_path=binary_path,
                analysis_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                duration=duration,
                overview=overview,
                key_findings="\n".join(f"- {f}" for f in key_findings),
                risk_score=risk_score,
                risk_level=risk_level,
                recommendations="\n".join(f"- {r}" for r in recommendations)
            )

            return summary

        except Exception as e:
            log.error(f"Failed to generate executive summary: {e}", exc_info=True)
            return "Executive summary generation failed"

    def _generate_technical_details(self, analysis_results: Dict[str, Any]) -> str:
        """Generate technical details section"""
        try:
            results = analysis_results.get("results", {})

            static_analysis = "No static analysis performed"
            if "static" in results:
                static_analysis = json.dumps(results["static"], indent=2)

            dynamic_analysis = "No dynamic analysis performed"
            if "dynamic" in results:
                dynamic_analysis = json.dumps(results["dynamic"], indent=2)

            security_analysis = "No security analysis performed"
            if "security" in results:
                security_analysis = json.dumps(results["security"], indent=2)

            vulnerabilities = []
            if "security" in results:
                vulnerabilities = results["security"].get("vulnerabilities", [])

            malware_behaviors = []
            if "dynamic" in results:
                malware_behaviors = results["dynamic"].get("malware_behaviors", [])

            template = self.report_templates["technical_details"]
            details = template.format(
                binary_path=analysis_results.get("binary_path", "unknown"),
                analysis_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                static_analysis=static_analysis,
                dynamic_analysis=dynamic_analysis,
                security_analysis=security_analysis,
                vulnerabilities=json.dumps(vulnerabilities, indent=2),
                malware_behaviors=json.dumps(malware_behaviors, indent=2)
            )

            return details

        except Exception as e:
            log.error(f"Failed to generate technical details: {e}", exc_info=True)
            return "Technical details generation failed"

    def _calculate_cvss_score(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate CVSS score based on analysis"""
        try:
            results = analysis_results.get("results", {})
            vulnerabilities = results.get("security", {}).get("vulnerabilities", [])

            if not vulnerabilities:
                return {
                    "base_score": 0.0,
                    "temporal_score": 0.0,
                    "metrics": {
                        "av": "N",
                        "ac": "L",
                        "pr": "N",
                        "ui": "N",
                        "s": "U",
                        "c": "N",
                        "i": "N",
                        "a": "N"
                    }
                }

            high_severity = sum(1 for v in vulnerabilities if v.get("severity") == "high")
            medium_severity = sum(1 for v in vulnerabilities if v.get("severity") == "medium")
            low_severity = sum(1 for v in vulnerabilities if v.get("severity") == "low")

            base_score = min(high_severity * 3.0 + medium_severity * 1.5 + low_severity * 0.5, 10.0)

            return {
                "base_score": round(base_score, 1),
                "temporal_score": round(base_score * 0.9, 1),
                "metrics": {
                    "av": "N" if high_severity > 0 else "L",
                    "ac": "L",
                    "pr": "N",
                    "ui": "N",
                    "s": "U",
                    "c": "H" if high_severity > 0 else "N",
                    "i": "H" if high_severity > 0 else "N",
                    "a": "H" if high_severity > 0 else "N"
                }
            }

        except Exception as e:
            log.error(f"Failed to calculate CVSS score: {e}", exc_info=True)
            return {"base_score": 0.0, "temporal_score": 0.0}

    def _perform_risk_assessment(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform overall risk assessment"""
        try:
            cvss_score = self._calculate_cvss_score(analysis_results)
            risk_score = self._calculate_risk_score(analysis_results)

            return {
                "cvss_score": cvss_score.get("base_score", 0.0),
                "custom_risk_score": risk_score,
                "risk_level": self._get_risk_level(risk_score),
                "factors": self._identify_risk_factors(analysis_results),
                "mitigation_priority": self._determine_mitigation_priority(risk_score)
            }

        except Exception as e:
            log.error(f"Failed to perform risk assessment: {e}", exc_info=True)
            return {"error": str(e)}

    def _calculate_risk_score(self, analysis_results: Dict[str, Any]) -> float:
        """Calculate custom risk score"""
        try:
            score = 0.0
            results = analysis_results.get("results", {})

            if "security" in results:
                vulnerabilities = results["security"].get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    severity = vuln.get("severity", "low")
                    if severity == "critical":
                        score += 2.0
                    elif severity == "high":
                        score += 1.5
                    elif severity == "medium":
                        score += 1.0
                    elif severity == "low":
                        score += 0.5

            if "dynamic" in results:
                dynamic = results["dynamic"]
                if dynamic.get("suspicious_activities"):
                    score += len(dynamic["suspicious_activities"]) * 0.5

            return min(score, 10.0)

        except Exception as e:
            log.error(f"Failed to calculate risk score: {e}", exc_info=True)
            return 0.0

    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score"""
        if score >= 8.0:
            return "Critical"
        elif score >= 6.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 2.0:
            return "Low"
        else:
            return "Minimal"

    def _identify_risk_factors(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Identify risk factors from analysis"""
        factors = []
        results = analysis_results.get("results", {})

        if "security" in results:
            vulnerabilities = results["security"].get("vulnerabilities", [])
            for vuln in vulnerabilities:
                factors.append(f"Vulnerability: {vuln.get('type', 'unknown')}")

        if "dynamic" in results:
            dynamic = results["dynamic"]
            if dynamic.get("network_events"):
                factors.append("Network activity detected")
            if dynamic.get("file_operations"):
                factors.append("File system modifications detected")

        return factors

    def _determine_mitigation_priority(self, score: float) -> str:
        """Determine mitigation priority"""
        if score >= 8.0:
            return "Immediate"
        elif score >= 6.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"

    def _generate_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        results = analysis_results.get("results", {})

        if "security" in results:
            vulnerabilities = results["security"].get("vulnerabilities", [])
            if vulnerabilities:
                recommendations.append("Review and address identified vulnerabilities")

        if "dynamic" in results:
            dynamic = results["dynamic"]
            if dynamic.get("suspicious_activities"):
                recommendations.append("Investigate suspicious runtime activities")
            if dynamic.get("network_events"):
                recommendations.append("Monitor and restrict network communications")

        recommendations.append("Implement regular security audits")
        recommendations.append("Keep systems and dependencies updated")

        return recommendations

    def _get_high_level_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Get high-level recommendations for executive summary"""
        return self._generate_recommendations(analysis_results)

    def _convert_to_html(self, report: Dict[str, Any]) -> str:
        """Convert report to HTML format"""
        try:
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {report['job_id']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; padding-bottom: 10px; }}
        .risk-critical {{ color: red; font-weight: bold; }}
        .risk-high {{ color: orange; font-weight: bold; }}
        .risk-medium {{ color: yellow; font-weight: bold; }}
        .risk-low {{ color: green; font-weight: bold; }}
        pre {{ background: #f4f4f4; padding: 15px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Security Analysis Report</h1>
    <p><strong>Job ID:</strong> {report['job_id']}</p>
    <p><strong>Binary:</strong> {report['binary_path']}</p>
    <p><strong>Generated:</strong> {report['generated_at']}</p>

    <h2>Executive Summary</h2>
    <pre>{report['executive_summary']}</pre>

    <h2>Risk Assessment</h2>
    <p><strong>Risk Score:</strong> {report['risk_assessment']['custom_risk_score']}/10</p>
    <p><strong>Risk Level:</strong> <span class="risk-{report['risk_assessment']['risk_level'].lower()}">{report['risk_assessment']['risk_level']}</span></p>

    <h2>CVSS Score</h2>
    <p><strong>Base Score:</strong> {report['cvss_score']['base_score']}</p>

    <h2>Recommendations</h2>
    <ul>
        {"".join(f"<li>{r}</li>" for r in report['recommendations'])}
    </ul>

    <h2>Technical Details</h2>
    <pre>{report['technical_details']}</pre>
</body>
</html>
"""
            return html

        except Exception as e:
            log.error(f"Failed to convert to HTML: {e}", exc_info=True)
            return ""

    def _convert_to_pdf(self, report: Dict[str, Any], job_id: str) -> str:
        """Convert report to PDF format"""
        try:
            html_content = self._convert_to_html(report)
            output_path = Path(settings.DATA_DIR) / f"{job_id}_report.html"

            output_path.write_text(html_content, encoding='utf-8')

            return str(output_path)

        except Exception as e:
            log.error(f"Failed to convert to PDF: {e}", exc_info=True)
            return ""


_report_agent_instance: Optional[ReportAgent] = None


def get_report_agent() -> ReportAgent:
    """Get or create report agent instance"""
    global _report_agent_instance
    if _report_agent_instance is None:
        _report_agent_instance = ReportAgent()
    return _report_agent_instance
