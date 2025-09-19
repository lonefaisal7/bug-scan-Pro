"""
Advanced reporting engine with vulnerability assessment
Generates professional reports with AI insights
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import uuid

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn

console = Console()


class VulnerabilityAssessment:
    """Advanced vulnerability assessment engine"""
    
    def __init__(self):
        self.vulnerability_patterns = {
            'admin_interfaces': {
                'patterns': ['admin', 'administrator', 'panel', 'control', 'manage', 'dashboard'],
                'severity': 'HIGH',
                'description': 'Administrative interface potentially exposed'
            },
            'development_environments': {
                'patterns': ['dev', 'test', 'staging', 'beta', 'qa', 'uat'],
                'severity': 'MEDIUM',
                'description': 'Development environment potentially exposed'
            },
            'backup_files': {
                'patterns': ['backup', 'bak', 'old', 'temp', 'archive', 'dump'],
                'severity': 'HIGH',
                'description': 'Backup files potentially accessible'
            },
            'database_interfaces': {
                'patterns': ['db', 'database', 'mysql', 'postgres', 'mongo', 'redis'],
                'severity': 'CRITICAL',
                'description': 'Database interface potentially exposed'
            },
            'api_endpoints': {
                'patterns': ['api', 'rest', 'graphql', 'webhook', 'service'],
                'severity': 'MEDIUM',
                'description': 'API endpoint discovered'
            },
            'file_systems': {
                'patterns': ['files', 'uploads', 'downloads', 'ftp', 'sftp'],
                'severity': 'MEDIUM',
                'description': 'File system interface exposed'
            }
        }
        
        self.high_risk_ports = {
            21: 'FTP - Potential data exposure',
            22: 'SSH - Remote access',
            23: 'Telnet - Insecure remote access',
            25: 'SMTP - Email server',
            53: 'DNS - Domain name service',
            80: 'HTTP - Web server',
            110: 'POP3 - Email retrieval',
            143: 'IMAP - Email access',
            443: 'HTTPS - Secure web server',
            993: 'IMAPS - Secure email access',
            995: 'POP3S - Secure email retrieval',
            1433: 'MSSQL - Database server',
            3306: 'MySQL - Database server',
            3389: 'RDP - Remote desktop',
            5432: 'PostgreSQL - Database server',
            6379: 'Redis - In-memory database',
            27017: 'MongoDB - NoSQL database'
        }
    
    async def assess_vulnerabilities(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Comprehensive vulnerability assessment"""
        assessment = {
            'scan_metadata': {
                'assessment_id': uuid.uuid4().hex,
                'timestamp': datetime.utcnow().isoformat(),
                'total_targets': len(scan_results),
                'assessment_version': '1.0.0'
            },
            'vulnerabilities': [],
            'risk_summary': {},
            'recommendations': [],
            'compliance_status': {}
        }
        
        console.print("[blue]🔍 Performing vulnerability assessment...[/blue]")
        
        # Analyze each result
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing vulnerabilities", total=len(scan_results))
            
            for result in scan_results:
                vulns = await self._analyze_single_result(result)
                assessment['vulnerabilities'].extend(vulns)
                progress.advance(task)
        
        # Generate risk summary
        assessment['risk_summary'] = self._calculate_risk_summary(
            assessment['vulnerabilities']
        )
        
        # Generate recommendations
        assessment['recommendations'] = self._generate_recommendations(
            assessment['vulnerabilities']
        )
        
        # Compliance assessment
        assessment['compliance_status'] = self._assess_compliance(
            scan_results, assessment['vulnerabilities']
        )
        
        return assessment
    
    async def _analyze_single_result(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a single scan result for vulnerabilities"""
        vulnerabilities = []
        
        hostname = result.get('host', result.get('target', ''))
        
        # Hostname-based vulnerability detection
        for vuln_type, vuln_info in self.vulnerability_patterns.items():
            for pattern in vuln_info['patterns']:
                if pattern in hostname.lower():
                    vulnerability = {
                        'id': f"VULN_{len(vulnerabilities)+1:04d}",
                        'type': vuln_type,
                        'severity': vuln_info['severity'],
                        'description': vuln_info['description'],
                        'target': hostname,
                        'pattern_match': pattern,
                        'confidence': 0.8,
                        'discovered_at': datetime.utcnow().isoformat()
                    }
                    
                    # Add HTTP-specific information if available
                    if 'http' in result:
                        http_info = result['http']
                        vulnerability.update({
                            'http_status': http_info.get('status'),
                            'server': http_info.get('server'),
                            'reachable': http_info.get('reachable', False)
                        })
                    
                    vulnerabilities.append(vulnerability)
                    break  # Only one pattern per type per target
        
        return vulnerabilities
    
    def _calculate_risk_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall risk summary"""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_score = 0
        
        severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            severity_counts[severity] += 1
            total_score += severity_scores.get(severity, 0)
        
        # Calculate risk level
        if severity_counts['CRITICAL'] > 0:
            risk_level = 'CRITICAL'
        elif severity_counts['HIGH'] > 3:
            risk_level = 'HIGH'
        elif severity_counts['HIGH'] > 0 or severity_counts['MEDIUM'] > 5:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'risk_score': total_score,
            'risk_level': risk_level,
            'assessment_summary': f"{len(vulnerabilities)} vulnerabilities found with {risk_level} overall risk"
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate actionable security recommendations"""
        recommendations = []
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Generate type-specific recommendations
        recommendation_templates = {
            'admin_interfaces': {
                'title': 'Secure Administrative Interfaces',
                'priority': 'HIGH',
                'actions': [
                    'Implement IP whitelisting for admin panels',
                    'Enable two-factor authentication',
                    'Use non-standard URLs for admin interfaces',
                    'Implement proper access controls'
                ]
            },
            'development_environments': {
                'title': 'Secure Development Environments',
                'priority': 'MEDIUM',
                'actions': [
                    'Remove or restrict access to development environments',
                    'Implement proper authentication',
                    'Ensure no sensitive data in dev environments',
                    'Use VPN access for internal systems'
                ]
            },
            'exposed_service': {
                'title': 'Secure Exposed Services',
                'priority': 'HIGH',
                'actions': [
                    'Review necessity of exposed services',
                    'Implement proper authentication',
                    'Use firewalls to restrict access',
                    'Keep services updated and patched'
                ]
            },
            'expired_certificate': {
                'title': 'Update SSL Certificates',
                'priority': 'HIGH',
                'actions': [
                    'Renew expired SSL certificates immediately',
                    'Implement automated certificate renewal',
                    'Monitor certificate expiration dates',
                    'Use certificate transparency monitoring'
                ]
            }
        }
        
        for vuln_type, vulns in vuln_by_type.items():
            if vuln_type in recommendation_templates:
                template = recommendation_templates[vuln_type]
                recommendation = {
                    'id': f"REC_{len(recommendations)+1:03d}",
                    'title': template['title'],
                    'priority': template['priority'],
                    'affected_targets': [v.get('target') for v in vulns],
                    'target_count': len(vulns),
                    'actions': template['actions'],
                    'risk_reduction': 'HIGH'
                }
                recommendations.append(recommendation)
        
        return recommendations
    
    def _assess_compliance(self, scan_results: List[Dict[str, Any]], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess compliance with security standards"""
        compliance = {
            'frameworks': {
                'OWASP_ASVS': self._assess_owasp_compliance(vulnerabilities),
                'NIST_CSF': self._assess_nist_compliance(vulnerabilities),
                'ISO_27001': self._assess_iso_compliance(vulnerabilities)
            },
            'overall_score': 0,
            'compliance_level': 'NON_COMPLIANT'
        }
        
        # Calculate overall compliance score
        scores = [f['score'] for f in compliance['frameworks'].values()]
        compliance['overall_score'] = sum(scores) / len(scores) if scores else 0
        
        if compliance['overall_score'] >= 90:
            compliance['compliance_level'] = 'FULLY_COMPLIANT'
        elif compliance['overall_score'] >= 70:
            compliance['compliance_level'] = 'MOSTLY_COMPLIANT'
        elif compliance['overall_score'] >= 50:
            compliance['compliance_level'] = 'PARTIALLY_COMPLIANT'
        else:
            compliance['compliance_level'] = 'NON_COMPLIANT'
        
        return compliance
    
    def _assess_owasp_compliance(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess OWASP ASVS compliance"""
        critical_issues = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
        high_issues = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
        
        # Simple scoring based on vulnerability counts
        score = max(0, 100 - (critical_issues * 20) - (high_issues * 10))
        
        return {
            'framework': 'OWASP ASVS 4.0',
            'score': score,
            'status': 'COMPLIANT' if score >= 80 else 'NON_COMPLIANT',
            'critical_issues': critical_issues,
            'high_issues': high_issues
        }
    
    def _assess_nist_compliance(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess NIST Cybersecurity Framework compliance"""
        total_vulns = len(vulnerabilities)
        score = max(0, 100 - (total_vulns * 5))
        
        return {
            'framework': 'NIST CSF 2.0',
            'score': score,
            'status': 'COMPLIANT' if score >= 75 else 'NON_COMPLIANT',
            'total_vulnerabilities': total_vulns
        }
    
    def _assess_iso_compliance(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess ISO 27001 compliance"""
        admin_vulns = len([v for v in vulnerabilities if 'admin' in v.get('type', '')])
        score = max(0, 100 - (admin_vulns * 15))
        
        return {
            'framework': 'ISO 27001:2022',
            'score': score,
            'status': 'COMPLIANT' if score >= 85 else 'NON_COMPLIANT',
            'admin_exposures': admin_vulns
        }


class AdvancedReportGenerator:
    """Advanced report generation with professional formatting"""
    
    def __init__(self):
        self.vulnerability_assessor = VulnerabilityAssessment()
    
    async def generate_executive_report(
        self,
        scan_results: List[Dict[str, Any]],
        scan_metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Generate executive-level security report"""
        console.print("[blue]📈 Generating executive report...[/blue]")
        
        # Perform vulnerability assessment
        vulnerability_assessment = await self.vulnerability_assessor.assess_vulnerabilities(
            scan_results
        )
        
        # Calculate scan statistics
        scan_stats = self._calculate_scan_statistics(scan_results)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            scan_stats, vulnerability_assessment
        )
        
        report = {
            'report_metadata': {
                'report_id': uuid.uuid4().hex,
                'generated_at': datetime.utcnow().isoformat(),
                'generator': 'Bug Scan Pro v1.0.0',
                'created_by': '@lonefaisal',
                'report_type': 'Executive Security Assessment',
                'format_version': '2.0'
            },
            'executive_summary': executive_summary,
            'scan_statistics': scan_stats,
            'vulnerability_assessment': vulnerability_assessment,
            'technical_details': {
                'scan_configuration': scan_metadata or {},
                'raw_results': scan_results[:100]  # Limit raw data
            },
            'appendices': {
                'methodology': self._get_methodology_info(),
                'glossary': self._get_security_glossary()
            }
        }
        
        return report
    
    def _calculate_scan_statistics(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate comprehensive scan statistics"""
        total_targets = len(scan_results)
        successful_scans = len([r for r in scan_results if r.get('success', False)])
        
        # HTTP statistics
        http_reachable = len([
            r for r in scan_results 
            if r.get('http', {}).get('reachable', False)
        ])
        
        # Response time statistics
        response_times = [
            r.get('response_time', 0) for r in scan_results 
            if r.get('response_time', 0) > 0
        ]
        
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            'total_targets_scanned': total_targets,
            'successful_scans': successful_scans,
            'success_rate_percentage': (successful_scans / total_targets * 100) if total_targets > 0 else 0,
            'http_reachable_targets': http_reachable,
            'http_reachability_rate': (http_reachable / total_targets * 100) if total_targets > 0 else 0,
            'average_response_time_ms': round(avg_response_time, 2),
            'fastest_response_ms': min(response_times) if response_times else 0,
            'slowest_response_ms': max(response_times) if response_times else 0
        }
    
    def _generate_executive_summary(self, scan_stats: Dict[str, Any], vuln_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        risk_summary = vuln_assessment.get('risk_summary', {})
        total_vulns = risk_summary.get('total_vulnerabilities', 0)
        risk_level = risk_summary.get('risk_level', 'UNKNOWN')
        
        # Generate key findings
        key_findings = []
        
        if total_vulns == 0:
            key_findings.append("No critical vulnerabilities identified")
        else:
            if risk_summary.get('severity_breakdown', {}).get('CRITICAL', 0) > 0:
                key_findings.append(f"CRITICAL: {risk_summary['severity_breakdown']['CRITICAL']} critical vulnerabilities require immediate attention")
            
            if risk_summary.get('severity_breakdown', {}).get('HIGH', 0) > 0:
                key_findings.append(f"HIGH: {risk_summary['severity_breakdown']['HIGH']} high-severity issues identified")
        
        # Success rate assessment
        success_rate = scan_stats.get('success_rate_percentage', 0)
        if success_rate > 90:
            key_findings.append("Excellent scan coverage achieved")
        elif success_rate > 70:
            key_findings.append("Good scan coverage with some unreachable targets")
        else:
            key_findings.append("Limited scan coverage - investigate connectivity issues")
        
        return {
            'overall_risk_level': risk_level,
            'total_vulnerabilities_found': total_vulns,
            'scan_success_rate': f"{success_rate:.1f}%",
            'key_findings': key_findings,
            'immediate_actions_required': total_vulns > 0,
            'compliance_concerns': risk_level in ['HIGH', 'CRITICAL']
        }
    
    def _get_methodology_info(self) -> Dict[str, Any]:
        """Get scanning methodology information"""
        return {
            'scanning_techniques': [
                'Passive subdomain discovery via Certificate Transparency',
                'DNS brute-force enumeration with wordlists',
                'HTTP/HTTPS reachability testing',
                'SSL/TLS certificate analysis',
                'Port scanning and service detection',
                'Vulnerability pattern matching'
            ],
            'data_sources': [
                'Certificate Transparency Logs (crt.sh)',
                'DNS resolution queries',
                'HTTP response analysis',
                'SSL certificate inspection',
                'Network connectivity tests'
            ],
            'analysis_methods': [
                'Pattern-based vulnerability detection',
                'Risk scoring algorithms',
                'Compliance framework assessment',
                'Statistical analysis of scan results'
            ]
        }
    
    def _get_security_glossary(self) -> Dict[str, str]:
        """Get security terminology glossary"""
        return {
            'Certificate Transparency': 'Public logs of SSL/TLS certificates for transparency and monitoring',
            'Subdomain Enumeration': 'Process of discovering subdomains of a target domain',
            'DNS Brute Force': 'Systematic testing of subdomain names against DNS servers',
            'SSL/TLS Certificate': 'Digital certificates used to secure communications',
            'Port Scanning': 'Technique to discover open network ports on target systems',
            'Vulnerability Assessment': 'Systematic evaluation of security weaknesses',
            'Risk Score': 'Numerical representation of overall security risk',
            'Compliance Framework': 'Set of guidelines for security and regulatory compliance'
        }
    
    async def export_report(
        self,
        report: Dict[str, Any],
        format_type: str = 'json',
        filename: Optional[str] = None
    ) -> str:
        """Export report in specified format"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"bugscanpro_executive_report_{timestamp}"
        
        if format_type.lower() == 'json':
            output_file = f"{filename}.json"
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        
        elif format_type.lower() == 'markdown':
            output_file = f"{filename}.md"
            md_content = self._generate_markdown_report(report)
            with open(output_file, 'w') as f:
                f.write(md_content)
        
        else:
            raise ValueError(f"Unsupported report format: {format_type}")
        
        console.print(f"[green]✅ Executive report exported: {output_file}[/green]")
        return output_file
    
    def _generate_markdown_report(self, report: Dict[str, Any]) -> str:
        """Generate Markdown report"""
        executive_summary = report.get('executive_summary', {})
        vulnerability_assessment = report.get('vulnerability_assessment', {})
        scan_stats = report.get('scan_statistics', {})
        
        md_content = f"""
# 🔍 Bug Scan Pro - Executive Security Report

**Generated:** {datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}  
**Made with ❤️ by [@lonefaisal](https://t.me/lonefaisal)**

---

## 🎯 Executive Summary

- **Total Vulnerabilities:** {executive_summary.get('total_vulnerabilities_found', 0)}
- **Overall Risk Level:** {executive_summary.get('overall_risk_level', 'Unknown')}
- **Scan Success Rate:** {executive_summary.get('scan_success_rate', '0%')}
- **Targets Scanned:** {scan_stats.get('total_targets_scanned', 0)}

### Key Findings:

"""
        
        for finding in executive_summary.get('key_findings', []):
            md_content += f"- {finding}\n"
        
        md_content += """

---

## 📉 Scan Performance Metrics

| Metric | Value |
|--------|-------|
"""
        
        for key, value in scan_stats.items():
            formatted_key = key.replace('_', ' ').title()
            md_content += f"| {formatted_key} | {value} |\n"
        
        md_content += """

---

## ⚠️ Vulnerability Assessment

"""
        
        vuln_summary = vulnerability_assessment.get('risk_summary', {})
        severity_breakdown = vuln_summary.get('severity_breakdown', {})
        
        for severity, count in severity_breakdown.items():
            if count > 0:
                icon = {
                    'CRITICAL': '🚨',
                    'HIGH': '🔴', 
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(severity, '⚪')
                
                md_content += f"- **{icon} {severity}:** {count} vulnerabilities\n"
        
        md_content += """

---

## 🛡️ Security Recommendations

"""
        
        for i, recommendation in enumerate(vulnerability_assessment.get('recommendations', []), 1):
            md_content += f"""
### {i}. {recommendation.get('title', 'Recommendation')}

**Priority:** {recommendation.get('priority', 'Medium')}  
**Affected Targets:** {recommendation.get('target_count', 0)}

**Actions:**
"""
            
            for action in recommendation.get('actions', []):
                md_content += f"- {action}\n"
            
            md_content += "\n"
        
        md_content += f"""
---

## 📞 Contact & Support

- **Creator:** [@lonefaisal](https://t.me/lonefaisal)
- **Networks:** [ARROW NETWORK](https://t.me/arrow_network) | [KMRI NETWORK](https://t.me/kmri_network_reborn)
- **GitHub:** [lonefaisal7/bug-scan-Pro](https://github.com/lonefaisal7/bug-scan-Pro)

---

*Report generated by Bug Scan Pro v1.0.0 - Professional Security Assessment Tool*
        """
        
        return md_content


if __name__ == "__main__":
    # Test the advanced reporting system
    import asyncio
    
    async def test_advanced_reporting():
        # Sample scan results for testing
        sample_results = [
            {
                'host': 'admin.example.com',
                'success': True,
                'http': {'reachable': True, 'status': 200, 'server': 'nginx'},
                'response_time': 150,
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'host': 'api.example.com', 
                'success': True,
                'http': {'reachable': True, 'status': 200, 'server': 'apache'},
                'response_time': 200,
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'host': 'dev.example.com',
                'success': True,
                'http': {'reachable': False},
                'response_time': 5000,
                'timestamp': datetime.utcnow().isoformat()
            }
        ]
        
        # Generate report
        reporter = AdvancedReportGenerator()
        
        console.print("[blue]📈 Testing advanced reporting...[/blue]")
        
        report = await reporter.generate_executive_report(sample_results)
        
        # Export in multiple formats
        json_file = await reporter.export_report(report, 'json', 'test_report')
        md_file = await reporter.export_report(report, 'markdown', 'test_report')
        
        console.print(f"[green]✅ Reports generated:")
        console.print(f"  📄 JSON: {json_file}")
        console.print(f"  📝 Markdown: {md_file}")
        
        # Display executive summary
        exec_summary = report['executive_summary']
        console.print(Panel(
            f"Risk Level: {exec_summary.get('overall_risk_level')}\n"
            f"Vulnerabilities: {exec_summary.get('total_vulnerabilities_found')}\n"
            f"Success Rate: {exec_summary.get('scan_success_rate')}",
            title="🏆 Executive Summary",
            border_style="green"
        ))
    
    asyncio.run(test_advanced_reporting())