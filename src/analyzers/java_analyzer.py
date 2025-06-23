import subprocess
import os
import re

class JavaAnalyzer:
    def __init__(self, rules="all", config=None):
        self.rules = rules
        self.config = config or {}


    def _run_javac(self, file_path):
        """Compile the Java file and capture errors"""
        issues = []
        try:
            result = subprocess.run(["javac", file_path], capture_output=True, text=True)
            if result.stderr:
                for line in result.stderr.splitlines():
                    match = re.match(r"(.*):(\d+): (.*)", line)
                    if match:
                        issues.append({
                            'type': 'javac',
                            'rule': 'javac_error',
                            'message': match.group(3).strip(),
                            'line': int(match.group(2)),
                            'column': 1,
                            'severity': 'high',
                            'file': file_path
                        })
        except Exception as e:
            issues.append({
                'type': 'error',
                'rule': 'javac_error',
                'message': str(e),
                'line': 1,
                'column': 1,
                'severity': 'high',
                'file': file_path
            })
        return issues

    def _run_checkstyle(self, file_path):
        """Run Checkstyle and collect issues"""
        issues = []
        try:
            result = subprocess.run(
                ["java", "-jar", "tools/checkstyle.jar", "-c", "google_checks.xml", file_path],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                parts = line.split(":")
                if len(parts) >= 4:
                    issues.append({
                        'type': 'checkstyle',
                        'rule': 'style_violation',
                        'message': parts[3].strip(),
                        'line': int(parts[1]),
                        'column': int(parts[2]),
                        'severity': 'medium',
                        'file': file_path
                    })
        except Exception as e:
            issues.append({
                'type': 'error',
                'rule': 'checkstyle_error',
                'message': str(e),
                'line': 1,
                'column': 1,
                'severity': 'high',
                'file': file_path
            })
        return issues

    def _check_security_issues(self, file_path):
        """Scan for risky patterns like Runtime.exec"""
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
                for idx, line in enumerate(lines, 1):
                    if 'Runtime.getRuntime().exec' in line:
                        issues.append({
                            'type': 'security',
                            'rule': 'dangerous_exec',
                            'message': 'Use of Runtime.exec() may lead to command injection',
                            'line': idx,
                            'column': line.index('Runtime.getRuntime().exec'),
                            'severity': 'high',
                            'file': file_path
                        })
        except Exception as e:
            issues.append({
                'type': 'error',
                'rule': 'file_read_error',
                'message': str(e),
                'line': 1,
                'column': 1,
                'severity': 'high',
                'file': file_path
            })
        return issues

    def _check_cfg_issues(self, file_path):
        """Simple CFG-based checks for Java code"""
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

    def analyze(self, file_path):
        """Analyze Java file and return issues"""
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
        issues.extend(self._run_javac(file_path))
        issues.extend(self._run_checkstyle(file_path))
        issues.extend(self._check_security_issues(file_path))
        # Add CFG-based issues
        issues.extend(self._check_cfg_issues(file_path))
        return issues
