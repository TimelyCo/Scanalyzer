"""
Regex-based code analyzer that uses regular expressions to detect patterns in code
"""

import re
from typing import List, Dict, Any

class RegexAnalyzer:
    """Analyzer that uses regular expressions to detect code patterns"""
    
    def __init__(self, rules="all", config=None):
        """Initialize the analyzer with rules and configuration"""
        self.rules = rules
        self.config = config or {}
        
        # Define regex patterns for different types of issues
        self.patterns = {
            'security': {
                'sql_injection': {
                    'pattern': r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE).*FROM.*WHERE.*=.*[\'"]\s*\+\s*[\w\.]+',
                    'message': 'Potential SQL injection vulnerability',
                    'severity': 'high'
                },
                'xss_vulnerability': {
                    'pattern': r'(?i)innerHTML\s*=\s*[\'"].*[\'"]\s*\+\s*[\w\.]+',
                    'message': 'Potential XSS vulnerability in innerHTML assignment',
                    'severity': 'high'
                },
                'hardcoded_password': {
                    'pattern': r'(?i)(password|passwd|pwd)\s*=\s*[\'"][^\'"]+[\'"]',
                    'message': 'Hardcoded password detected',
                    'severity': 'high'
                }
            },
            'performance': {
                'inefficient_loop': {
                    'pattern': r'for\s*\(\s*[^;]+\s*;\s*[^;]+\s*;\s*[^)]+\s*\)\s*{[^}]*\s*\+\s*=\s*[\'"]',
                    'message': 'Inefficient string concatenation in loop',
                    'severity': 'medium'
                },
                'nested_loop': {
                    'pattern': r'for\s*\([^)]+\)\s*{[^}]*for\s*\([^)]+\)',
                    'message': 'Nested loops detected, consider optimization',
                    'severity': 'medium'
                }
            },
            'style': {
                'long_line': {
                    'pattern': r'^.{120,}$',
                    'message': 'Line exceeds 120 characters',
                    'severity': 'low'
                },
                'inconsistent_indentation': {
                    'pattern': r'^(?:\t+|\s{2,})(?:\t|\s{2,})',
                    'message': 'Inconsistent indentation detected',
                    'severity': 'low'
                },
                'missing_docstring': {
                    'pattern': r'^(?!\s*[\'"]{3}[\s\S]*?[\'"]{3}\s*$)def\s+\w+\s*\(',
                    'message': 'Function missing docstring',
                    'severity': 'low'
                }
            },
            'error_handling': {
                'bare_except': {
                    'pattern': r'except\s*:',
                    'message': 'Bare except clause detected',
                    'severity': 'medium'
                },
                'swallowed_exception': {
                    'pattern': r'except\s+\w+\s*as\s+\w+\s*:\s*pass',
                    'message': 'Exception is caught but not handled',
                    'severity': 'medium'
                }
            }
        }
    
    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze a file using regex patterns"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                lines = content.split('\n')
                
                # Determine file type for language-specific patterns
                file_extension = file_path.split('.')[-1].lower()
                
                # Apply patterns based on rules
                for category, patterns in self.patterns.items():
                    if self.rules != "all" and self.rules != category:
                        continue
                        
                    for rule_name, rule_info in patterns.items():
                        # Skip language-specific patterns if not applicable
                        if 'language' in rule_info and rule_info['language'] != file_extension:
                            continue
                            
                        pattern = re.compile(rule_info['pattern'])
                        
                        # Search for matches
                        for line_num, line in enumerate(lines, 1):
                            matches = pattern.finditer(line)
                            for match in matches:
                                issues.append({
                                    'type': category,
                                    'rule': rule_name,
                                    'message': rule_info['message'],
                                    'line': line_num,
                                    'column': match.start() + 1,
                                    'severity': rule_info['severity'],
                                    'file': file_path,
                                    'match': match.group(0)
                                })
                
                # Additional analysis for specific file types
                if file_extension == 'py':
                    issues.extend(self._analyze_python_specific(content, file_path))
                elif file_extension == 'js':
                    issues.extend(self._analyze_javascript_specific(content, file_path))
                elif file_extension == 'java':
                    issues.extend(self._analyze_java_specific(content, file_path))
                
        except Exception as e:
            issues.append({
                'type': 'error',
                'rule': 'file_error',
                'message': f'Error analyzing file: {str(e)}',
                'line': 1,
                'column': 1,
                'severity': 'high',
                'file': file_path
            })
        
        return issues
    
    def _analyze_python_specific(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Python-specific regex analysis"""
        issues = []
        
        # Check for Python-specific patterns
        python_patterns = {
            'global_variable': {
                'pattern': r'global\s+\w+',
                'message': 'Global variable usage detected',
                'severity': 'medium'
            },
            'mutable_default': {
                'pattern': r'def\s+\w+\s*\([^)]*=\s*[{\[]',
                'message': 'Mutable default argument detected',
                'severity': 'medium'
            }
        }
        
        for rule_name, rule_info in python_patterns.items():
            pattern = re.compile(rule_info['pattern'])
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                issues.append({
                    'type': 'python_specific',
                    'rule': rule_name,
                    'message': rule_info['message'],
                    'line': line_num,
                    'column': match.start() - content.rfind('\n', 0, match.start()),
                    'severity': rule_info['severity'],
                    'file': file_path,
                    'match': match.group(0)
                })
        
        return issues
    
    def _analyze_javascript_specific(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """JavaScript-specific regex analysis"""
        issues = []
        
        # Check for JavaScript-specific patterns
        js_patterns = {
            'eval_usage': {
                'pattern': r'eval\s*\(',
                'message': 'Use of eval() detected',
                'severity': 'high'
            },
            'console_log': {
                'pattern': r'console\.log\s*\(',
                'message': 'Console.log statement in production code',
                'severity': 'low'
            }
        }
        
        for rule_name, rule_info in js_patterns.items():
            pattern = re.compile(rule_info['pattern'])
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                issues.append({
                    'type': 'javascript_specific',
                    'rule': rule_name,
                    'message': rule_info['message'],
                    'line': line_num,
                    'column': match.start() - content.rfind('\n', 0, match.start()),
                    'severity': rule_info['severity'],
                    'file': file_path,
                    'match': match.group(0)
                })
        
        return issues
    
    def _analyze_java_specific(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Java-specific regex analysis"""
        issues = []
        
        # Check for Java-specific patterns
        java_patterns = {
            'system_out': {
                'pattern': r'System\.out\.(print|println)\s*\(',
                'message': 'Use of System.out in production code',
                'severity': 'low'
            },
            'raw_type': {
                'pattern': r'ArrayList\s*<>\s*\(\)',
                'message': 'Raw type usage detected',
                'severity': 'medium'
            }
        }
        
        for rule_name, rule_info in java_patterns.items():
            pattern = re.compile(rule_info['pattern'])
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                issues.append({
                    'type': 'java_specific',
                    'rule': rule_name,
                    'message': rule_info['message'],
                    'line': line_num,
                    'column': match.start() - content.rfind('\n', 0, match.start()),
                    'severity': rule_info['severity'],
                    'file': file_path,
                    'match': match.group(0)
                })
        
        return issues 