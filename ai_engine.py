"""
AI-Powered Security Scanner Engine
Provides intelligent template selection, risk assessment, and threat analysis
"""

import json
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import logging
from datetime import datetime

@dataclass
class AIAnalysis:
    """AI analysis results"""
    confidence: float
    risk_score: int  # 1-10 scale
    summary: str
    recommendations: List[str]
    threat_indicators: List[str]

@dataclass
class SmartTemplateSelection:
    """AI-selected templates for target"""
    templates: List[str]
    reasoning: str
    estimated_time: int  # seconds
    priority_areas: List[str]

class AISecurityEngine:
    """AI-powered security analysis engine"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
    def _load_vulnerability_patterns(self) -> Dict[str, Any]:
        """Load known vulnerability patterns for AI analysis"""
        return {
            "sql_injection": {
                "indicators": ["error", "mysql", "syntax", "query", "database"],
                "severity_multiplier": 1.5,
                "common_paths": ["/login", "/search", "/admin", "/api"]
            },
            "xss": {
                "indicators": ["script", "alert", "javascript", "onload", "onerror"],
                "severity_multiplier": 1.3,
                "common_paths": ["/search", "/comment", "/profile", "/form"]
            },
            "lfi": {
                "indicators": ["../", "etc/passwd", "windows/win.ini", "file://"],
                "severity_multiplier": 1.4,
                "common_paths": ["/download", "/file", "/include", "/load"]
            },
            "rce": {
                "indicators": ["system", "exec", "cmd", "shell", "command"],
                "severity_multiplier": 2.0,
                "common_paths": ["/admin", "/upload", "/api", "/exec"]
            }
        }
    
    def analyze_target_intelligence(self, target: str, reconnaissance_data: Dict[str, Any]) -> SmartTemplateSelection:
        """AI-powered smart template selection based on target analysis"""
        self.logger.info(f"AI analyzing target: {target}")
        
        # Analyze target characteristics
        tech_stack = self._detect_technology_stack(reconnaissance_data)
        attack_surface = self._analyze_attack_surface(reconnaissance_data)
        risk_areas = self._identify_risk_areas(target, tech_stack, attack_surface)
        
        # Select optimal templates
        templates = self._select_smart_templates(tech_stack, risk_areas)
        estimated_time = self._estimate_scan_time(templates, len(attack_surface.get('subdomains', [target])))
        
        reasoning = f"""
        AI Target Analysis:
        • Technology Stack: {', '.join(tech_stack)}
        • Attack Surface: {len(attack_surface.get('subdomains', []))} domains
        • High-Risk Areas: {', '.join(risk_areas)}
        • Optimized Templates: {len(templates)} selected
        """
        
        return SmartTemplateSelection(
            templates=templates,
            reasoning=reasoning.strip(),
            estimated_time=estimated_time,
            priority_areas=risk_areas
        )
    
    def _detect_technology_stack(self, recon_data: Dict[str, Any]) -> List[str]:
        """Detect technology stack from reconnaissance data"""
        tech_indicators = {
            "php": ["php", ".php", "phpmyadmin", "wordpress", "drupal"],
            "java": ["java", ".jsp", ".do", "tomcat", "spring", "struts"],
            "asp": [".asp", ".aspx", "iis", "microsoft", "sharepoint"],
            "python": ["django", "flask", "python", ".py"],
            "nodejs": ["node", "express", "npm", "javascript"],
            "wordpress": ["wp-", "wordpress", "wp-content", "wp-admin"],
            "joomla": ["joomla", "com_", "index.php?option=com_"],
            "drupal": ["drupal", "node/", "user/login"]
        }
        
        detected_tech = []
        recon_text = json.dumps(recon_data).lower()
        
        for tech, indicators in tech_indicators.items():
            if any(indicator in recon_text for indicator in indicators):
                detected_tech.append(tech)
        
        return detected_tech or ["generic"]
    
    def _analyze_attack_surface(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack surface from reconnaissance data"""
        return {
            "subdomains": recon_data.get("subdomains", []),
            "open_ports": recon_data.get("ports", []),
            "technologies": recon_data.get("technologies", []),
            "endpoints": recon_data.get("endpoints", [])
        }
    
    def _identify_risk_areas(self, target: str, tech_stack: List[str], attack_surface: Dict[str, Any]) -> List[str]:
        """Identify high-risk areas based on AI analysis"""
        risk_areas = []
        
        # Technology-based risks
        high_risk_tech = {
            "php": ["sql-injection", "lfi", "rce"],
            "wordpress": ["plugin-vulns", "sql-injection", "xss"],
            "java": ["deserialization", "xxe", "ssrf"],
            "asp": ["viewstate", "sql-injection", "path-traversal"]
        }
        
        for tech in tech_stack:
            if tech in high_risk_tech:
                risk_areas.extend(high_risk_tech[tech])
        
        # Domain-based risks
        if "admin" in target or "test" in target or "dev" in target:
            risk_areas.extend(["exposed-admin", "debug-info", "default-creds"])
        
        return list(set(risk_areas))
    
    def _select_smart_templates(self, tech_stack: List[str], risk_areas: List[str]) -> List[str]:
        """AI-powered template selection"""
        base_templates = [
            "http/vulnerabilities/",
            "http/exposures/",
            "http/misconfiguration/"
        ]
        
        # Technology-specific templates
        tech_templates = {
            "php": ["http/vulnerabilities/sql-injection/", "http/vulnerabilities/lfi/"],
            "wordpress": ["http/vulnerabilities/wordpress/", "http/exposures/configs/"],
            "java": ["http/vulnerabilities/xxe/", "http/vulnerabilities/deserialization/"],
            "asp": ["http/vulnerabilities/generic/", "http/exposures/"]
        }
        
        # Risk-based templates
        risk_templates = {
            "sql-injection": ["http/vulnerabilities/sql-injection/"],
            "xss": ["http/vulnerabilities/xss/"],
            "lfi": ["http/vulnerabilities/lfi/"],
            "rce": ["http/vulnerabilities/generic/"]
        }
        
        selected = base_templates.copy()
        
        # Add tech-specific templates
        for tech in tech_stack:
            if tech in tech_templates:
                selected.extend(tech_templates[tech])
        
        # Add risk-based templates
        for risk in risk_areas:
            if risk in risk_templates:
                selected.extend(risk_templates[risk])
        
        return list(set(selected))
    
    def _estimate_scan_time(self, templates: int, domains: int) -> int:
        """Estimate scan time based on templates and domains"""
        base_time = 30  # Base time in seconds
        template_factor = len(templates) * 10
        domain_factor = domains * 15
        return base_time + template_factor + domain_factor
    
    def assess_vulnerability_risk(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """AI-powered risk assessment and prioritization"""
        self.logger.info("AI assessing vulnerability risks...")
        
        assessed_vulns = []
        for vuln in vulnerabilities:
            ai_analysis = self._analyze_vulnerability_context(vuln)
            vuln_copy = vuln.copy()
            vuln_copy['ai_analysis'] = ai_analysis
            vuln_copy['ai_risk_score'] = ai_analysis.risk_score
            assessed_vulns.append(vuln_copy)
        
        # Sort by AI risk score (highest first)
        assessed_vulns.sort(key=lambda x: x.get('ai_risk_score', 0), reverse=True)
        return assessed_vulns
    
    def _analyze_vulnerability_context(self, vuln: Dict[str, Any]) -> AIAnalysis:
        """Analyze vulnerability context using AI patterns"""
        vuln_text = json.dumps(vuln).lower()
        
        # Calculate base risk score
        severity_scores = {"critical": 10, "high": 8, "medium": 6, "low": 4, "info": 2}
        base_score = severity_scores.get(vuln.get('severity', 'medium').lower(), 6)
        
        # AI enhancement factors
        risk_multiplier = 1.0
        threat_indicators = []
        
        # Check for high-impact patterns
        for vuln_type, patterns in self.vulnerability_patterns.items():
            if any(indicator in vuln_text for indicator in patterns['indicators']):
                risk_multiplier *= patterns['severity_multiplier']
                threat_indicators.append(vuln_type)
        
        # Context-based adjustments
        if any(path in vuln_text for path in ['/admin', '/login', '/api']):
            risk_multiplier *= 1.3
            threat_indicators.append("sensitive_endpoint")
        
        if any(keyword in vuln_text for keyword in ['authentication', 'bypass', 'privilege']):
            risk_multiplier *= 1.4
            threat_indicators.append("auth_bypass")
        
        final_score = min(10, int(base_score * risk_multiplier))
        confidence = min(1.0, 0.6 + (len(threat_indicators) * 0.1))
        
        # Generate AI summary
        summary = self._generate_vulnerability_summary(vuln, threat_indicators, final_score)
        recommendations = self._generate_recommendations(vuln, threat_indicators)
        
        return AIAnalysis(
            confidence=confidence,
            risk_score=final_score,
            summary=summary,
            recommendations=recommendations,
            threat_indicators=threat_indicators
        )
    
    def _generate_vulnerability_summary(self, vuln: Dict[str, Any], indicators: List[str], risk_score: int) -> str:
        """Generate plain language summary of vulnerability"""
        vuln_name = vuln.get('template-id', 'Unknown Vulnerability')
        severity = vuln.get('severity', 'medium').upper()
        
        risk_level = "CRITICAL" if risk_score >= 9 else "HIGH" if risk_score >= 7 else "MEDIUM" if risk_score >= 5 else "LOW"
        
        summary = f"🚨 {risk_level} RISK: {vuln_name} ({severity} severity)"
        
        if "sql_injection" in indicators:
            summary += "\n💉 Potential SQL injection - attackers could access/modify database"
        if "xss" in indicators:
            summary += "\n🔗 Cross-site scripting risk - user data could be stolen"
        if "rce" in indicators:
            summary += "\n💻 Remote code execution possible - full system compromise risk"
        if "lfi" in indicators:
            summary += "\n📁 File inclusion vulnerability - sensitive files could be exposed"
        if "auth_bypass" in indicators:
            summary += "\n🔐 Authentication bypass - unauthorized access possible"
        
        return summary
    
    def _generate_recommendations(self, vuln: Dict[str, Any], indicators: List[str]) -> List[str]:
        """Generate AI-powered recommendations"""
        recommendations = ["Verify vulnerability manually", "Apply security patches immediately"]
        
        if "sql_injection" in indicators:
            recommendations.extend([
                "Use parameterized queries/prepared statements",
                "Implement input validation and sanitization",
                "Apply principle of least privilege to database accounts"
            ])
        
        if "xss" in indicators:
            recommendations.extend([
                "Implement Content Security Policy (CSP)",
                "Sanitize and encode all user inputs",
                "Use secure coding practices for output encoding"
            ])
        
        if "rce" in indicators:
            recommendations.extend([
                "Disable dangerous functions and system calls",
                "Implement strict input validation",
                "Use application sandboxing and containerization"
            ])
        
        if "auth_bypass" in indicators:
            recommendations.extend([
                "Implement multi-factor authentication",
                "Review and strengthen authentication logic",
                "Conduct security code review"
            ])
        
        return recommendations
    
    def generate_executive_summary(self, scan_results: Dict[str, Any], ai_analysis: List[Dict[str, Any]]) -> str:
        """Generate executive summary in plain language"""
        total_vulns = len(ai_analysis)
        critical_vulns = len([v for v in ai_analysis if v.get('ai_risk_score', 0) >= 9])
        high_vulns = len([v for v in ai_analysis if v.get('ai_risk_score', 0) >= 7])
        
        summary = f"""
AI SECURITY ASSESSMENT SUMMARY

RISK OVERVIEW:
• Total Vulnerabilities Found: {total_vulns}
• Critical Risk Issues: {critical_vulns}
• High Risk Issues: {high_vulns}
• Overall Security Posture: {'POOR' if critical_vulns > 0 else 'MODERATE' if high_vulns > 0 else 'GOOD'}

TOP THREATS:
{chr(10).join([f"• {v.get('ai_analysis', {}).get('summary', 'Unknown threat')}" for v in ai_analysis[:3]])}

IMMEDIATE ACTIONS REQUIRED:
• Patch {critical_vulns + high_vulns} high-priority vulnerabilities
• Review and strengthen input validation mechanisms
• Implement proper security headers and configurations
• Conduct security code review and testing
• Schedule regular security assessments

SCAN DETAILS:
• Target: {scan_results.get('target', 'Unknown')}
• Scan Duration: {scan_results.get('runtime', 'Unknown')}
• Tools Used: {scan_results.get('tools_used', 0)}
• AI Confidence: {confidence * 100:.1f}%
"""
        
        return summary.strip()
