"""
C++ code analyzer that detects common issues in C++ code, written in Python
"""

import os
import re
import json
import subprocess
import tempfile
from typing import List, Dict, Any, Optional, Union

class CppAnalyzer:
    """Analyzer for C++ source code"""
    
    def __init__(self, rules="all", config=None):
        """Initialize the analyzer with rules and configuration"""
        self.rules = rules
        self.config = config or {}
        
    def _run_clang_tidy(self, file_path: str) -> List[Dict[str, Any]]:
        """Run clang-tidy on the file and capture results"""
        issues = []
        
        try:
            # Create a compilation database for clang-tidy
            # This is a simple version - in practice, you might need more compiler flags
            compile_commands = [{
                "directory": os.path.dirname(os.path.abspath(file_path)),
                "command": f"g++ -std=c++17 -c {file_path}",
                "file": file_path
            }]
            
            # Write compilation database to a temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(compile_commands, f)
                compile_db_path = f.name
            
            # Configure clang-tidy checks based on rules
            checks = "*"
            if self.rules == "security":
                checks = "clang-analyzer-security.*,cert-*"
            elif self.rules == "performance":
                checks = "performance-*,clang-analyzer-cplusplus.Move,clang-analyzer-core.uninitialized.*"
            elif self.rules == "style":
                checks = "readability-*,modernize-*,clang-analyzer-cplusplus.PlacementNew"
                
            # Run clang-tidy
            cmd = [
                "clang-tidy",
                f"-checks={checks}",
                "-p", compile_db_path,
                file_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse the output
            output = result.stdout + result.stderr
            
            # Pattern to match clang-tidy output
            pattern = re.compile(r"([\w/\.]+):(\d+):(\d+): (warning|error): (.*?) \[([\w\-\.]+)\]")
            
            for match in pattern.finditer(output):
                file_name = match.group(1)
                line = int(match.group(2))
                column = int(match.group(3))
                level = match.group(4)
                message = match.group(5)
                rule_id = match.group(6)
                
                # Determine severity
                severity = "medium"
                if level == "error":
                    severity = "high"
                elif level == "warning":
                    severity = "medium"
                
                issues.append({
                    'type': 'clang-tidy',
                    'rule': rule_id,
                    'message': message,
                    'line': line,
                    'column': column,
                    'severity': severity,
                    'file': file_path
                })
                
            # Clean up temporary compilation database
            os.unlink(compile_db_path)
            
        except Exception as e:
            issues.append({
                'type': 'error',
                'rule': 'clang_tidy_error',
                'message': f'Error running clang-tidy: {str(e)}',
                'line': 1,
                'column': 1,
                'severity': 'medium',
                'file': file_path
            })
        
        return issues
    
    def _run_cppcheck(self, file_path: str) -> List[Dict[str, Any]]:
        """Run cppcheck on the file and capture results"""
        issues = []
        
        try:
            # Configure cppcheck arguments
            cmd = [
                "cppcheck",
                "--enable=all",
                "--template={file}:{line}:{column}:{severity}:{id}:{message}",
                file_path
            ]
            
            # Run cppcheck
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse the output
            output = result.stderr  # cppcheck outputs to stderr
            
            # Pattern to match cppcheck output
            pattern = re.compile(r"([\w/\.]+):(\d+):(\d+):(error|warning|style|performance|portability|information):(\w+):(.*)")
            
            for match in pattern.finditer(output):
                file_name = match.group(1)
                line = int(match.group(2))
                column = int(match.group(3))
                level = match.group(4)
                rule_id = match.group(5)
                message = match.group(6)
                
                # Determine severity
                severity = "medium"
                if level == "error":
                    severity = "high"
                elif level == "warning":
                    severity = "medium"
                elif level in ["style", "performance", "portability", "information"]:
                    severity = "low"
                
                issues.append({
                    'type': 'cppcheck',
                    'rule': rule_id,
                    'message': message,
                    'line': line,
                    'column': column,
                    'severity': severity,
                    'file': file_path
                })
                
        except Exception as e:
            issues.append({
                'type': 'error',
                'rule': 'cppcheck_error',
                'message': f'Error running cppcheck: {str(e)}',
                'line': 1,
                'column': 1,
                'severity': 'medium',
                'file': file_path
            })
        
        return issues
    
    def _check_security_issues(self, file_path: str) -> List[Dict[str, Any]]:
        """Check for security issues using regex patterns"""
        issues = []
        
        # Define patterns for potentially dangerous functions
        dangerous_functions = {
            r'\bsystem\s*\(': 'Command injection risk with system()',
            r'\bexec\s*\(': 'Command injection risk with exec()',
            r'\bstrcpy\s*\(': 'Buffer overflow risk with strcpy()',
            r'\bstrcat\s*\(': 'Buffer overflow risk with strcat()',
            r'\bgets\s*\(': 'Buffer overflow risk with gets()',
            r'\bmemcpy\s*\(': 'Potential buffer overflow with memcpy()',
            r'\bscanf\s*\(': 'Format string vulnerability with scanf()'
        }
        
        try:
            # Read the file
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
                
            # Check each line for dangerous functions
            for line_num, line in enumerate(lines, 1):
                for pattern, message in dangerous_functions.items():
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        # Skip if in a comment
                        if '//' in line[:match.start()]:
                            comment_pos = line.find('//')
                            if comment_pos < match.start():
                                continue
                                
                        issues.append({
                            'type': 'security',
                            'rule': f"unsafe_{match.group(0).strip('()')}",
                            'message': message,
                            'line': line_num,
                            'column': match.start() + 1,
                            'severity': 'high',
                            'file': file_path
                        })
        
        except Exception as e:
            issues.append({
                'type': 'error',
                'rule': 'security_check_error',
                'message': f'Error checking security issues: {str(e)}',
                'line': 1,
                'column': 1,
                'severity': 'medium',
                'file': file_path
            })
        
        return issues
    
    def _check_performance_issues(self, file_path: str) -> List[Dict[str, Any]]:
        """Check for performance issues using regex patterns"""
        issues = []
        
        # Track if we're inside a loop
        in_loop = False
        loop_depth = 0
        loop_start_line = 0
        
        # Expensive operations to check for in loops
        expensive_operations = {
            r'\bnew\b': 'memory allocation',
            r'\bdelete\b': 'memory deallocation',
            r'\bmalloc\s*\(': 'memory allocation',
            r'\bfree\s*\(': 'memory deallocation',
            r'\bsort\s*\(': 'sorting operation'
        }
        
        try:
            # Read the file
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
                
            # Simple parser to detect loops and operations inside them
            for line_num, line in enumerate(lines, 1):
                # Check for loop start
                if re.search(r'\b(for|while|do)\b.*\{', line) or (re.search(r'\b(for|while|do)\b', line) and not re.search(r';', line)):
                    in_loop = True
                    loop_depth += 1
                    loop_start_line = line_num
                
                # Check for loop end
                if in_loop and re.search(r'\}', line):
                    loop_depth -= 1
                    if loop_depth == 0:
                        in_loop = False
                
                # Check for expensive operations in loops
                if in_loop:
                    for pattern, operation in expensive_operations.items():
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            # Skip if in a comment
                            if '//' in line[:match.start()]:
                                comment_pos = line.find('//')
                                if comment_pos < match.start():
                                    continue
                                    
                            issues.append({
                                'type': 'performance',
                                'rule': 'expensive_operation_in_loop',
                                'message': f'Expensive {operation} inside a loop started at line {loop_start_line}',
                                'line': line_num,
                                'column': match.start() + 1,
                                'severity': 'medium',
                                'file': file_path
                            })
        
        except Exception as e:
            issues.append({
                'type': 'error',
                'rule': 'performance_check_error',
                'message': f'Error checking performance issues: {str(e)}',
                'line': 1,
                'column': 1,
                'severity': 'medium',
                'file': file_path
            })
        
        return issues
    
    def _check_cfg_issues(self, file_path: str):
        """Simple CFG-based checks for C++ code"""
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
                for idx, line in enumerate(lines, 1):
                    # Unreachable code: code after return
                    if 'return' in line:
                        if idx < len(lines):
                            next_line = lines[idx].strip()
                            if next_line and not next_line.startswith('//'):
                                issues.append({
                                    'type': 'cfg',
                                    'rule': 'unreachable',
                                    'message': 'Code after return is unreachable',
                                    'line': idx + 1,
                                    'column': 1,
                                    'severity': 'medium',
                                    'file': file_path
                                })
                    # Infinite loop: while(true)
                    if 'while(true)' in line.replace(' ', ''):
                        issues.append({
                            'type': 'cfg',
                            'rule': 'infinite_loops',
                            'message': 'Potential infinite loop detected',
                            'line': idx,
                            'column': 1,
                            'severity': 'medium',
                            'file': file_path
                        })
                    # Exception path: try/catch
                    if 'try' in line:
                        # Look ahead for catch
                        for j in range(idx, min(idx+10, len(lines))):
                            if 'catch' in lines[j]:
                                issues.append({
                                    'type': 'cfg',
                                    'rule': 'exception_paths',
                                    'message': 'Exception handling path (try/catch) detected',
                                    'line': idx,
                                    'column': 1,
                                    'severity': 'medium',
                                    'file': file_path
                                })
                                break
        except Exception as e:
            pass
        return issues
    
    def analyze(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze C++ file and return issues"""
        if not os.path.exists(file_path):
            return [{
                'type': 'error',
                'rule': 'file_not_found',
                'message': f'File not found: {file_path}',
                'line': 1,
                'column': 1,
                'severity': 'high',
                'file': file_path
            }]
        
        issues = []
        
        # Run different checks based on rules
        if self.rules in ["all", "security"]:
            security_issues = self._check_security_issues(file_path)
            issues.extend(security_issues)
        
        if self.rules in ["all", "performance"]:
            performance_issues = self._check_performance_issues(file_path)
            issues.extend(performance_issues)
        
        # Run external tools for additional checks
        clang_tidy_issues = self._run_clang_tidy(file_path)
        issues.extend(clang_tidy_issues)
        
        cppcheck_issues = self._run_cppcheck(file_path)
        issues.extend(cppcheck_issues)
        
        # Add CFG-based issues
        issues.extend(self._check_cfg_issues(file_path))
        
        return issues


def analyze_file(file_path: str, rules: str = "all", output_format: str = "json") -> None:
    """Analyze a C++ file and print results in the specified format"""
    analyzer = CppAnalyzer(rules)
    issues = analyzer.analyze(file_path)
    
    if output_format == "json":
        print(json.dumps(issues, indent=2))
    else:
        # Plain text output
        print(f"Analysis results for {file_path}:")
        for issue in issues:
            severity_marker = {
                "high": "!!!",
                "medium": "!!",
                "low": "!"
            }.get(issue['severity'], "!")
            
            print(f"{severity_marker} {issue['file']}:{issue['line']}:{issue['column']} - {issue['message']} [{issue['rule']}]")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze C++ code for common issues")
    parser.add_argument("file", help="C++ file to analyze")
    parser.add_argument("--rules", choices=["all", "security", "performance", "style"], 
                        default="all", help="Type of rules to check")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format")
    
    args = parser.parse_args()
    analyze_file(args.file, args.rules, args.format)