import os
import re

class JavaScriptAnalyzer:
    """Analyzer for JavaScript source code"""

    def __init__(self, rules="all", config=None):
        self.rules = rules
        self.config = config or {}

    def analyze(self, file_path):
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

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            return [{
                'type': 'error',
                'rule': 'read_error',
                'message': str(e),
                'line': 1,
                'column': 1,
                'severity': 'high',
                'file': file_path
            }]

        # Add CFG-based issues
        issues.extend(self._check_cfg_issues(file_path))

        unused_vars = set()
        used_vars = set()

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()

            # Security issues
            if 'eval(' in stripped:
                issues.append(self._issue("security", "unsafe_eval", "Use of eval()", idx, file_path))
            if 'exec(' in stripped:
                issues.append(self._issue("security", "unsafe_exec", "Use of exec()", idx, file_path))
            if 'require("child_process")' in stripped:
                issues.append(self._issue("security", "child_process", "Use of child_process module", idx, file_path))

            # Performance issues
            if 'JSON.parse(JSON.stringify(' in stripped:
                issues.append(self._issue("performance", "inefficient_deep_copy", "Inefficient deep copy", idx, file_path))
            if re.search(r'result\s*=\s*result\.concat\(\[.*\]\)', stripped):
                issues.append(self._issue("performance", "inefficient_concat", "Inefficient use of concat in loop", idx, file_path))

            # Nested loop detection removed

            # Unused variables (simple heuristic)
            match = re.findall(r'let\s+(\w+)', stripped)
            for var in match:
                unused_vars.add(var)

            for var in list(unused_vars):
                if re.search(rf'\b{var}\b', stripped) and not re.search(rf'let\s+{var}', stripped):
                    used_vars.add(var)

            # Unreachable code
            if re.search(r'return\b.*', stripped) and idx + 1 < len(lines):
                next_line = lines[idx].strip()
                if next_line and not next_line.startswith('//'):
                    issues.append(self._issue("logical", "unreachable_code", "Code after return is unreachable", idx + 1, file_path))

        for var in unused_vars - used_vars:
            issues.append(self._issue("style", "unused_variable", f"Variable '{var}' declared but not used", 1, file_path))

        return issues

    def _issue(self, type_, rule, message, line, file_path, severity=None):
        return {
            'type': type_,
            'rule': rule,
            'message': message,
            'line': line,
            'column': 1,
            'severity': severity or self._severity_for_rule(type_, rule),
            'file': file_path
        }

    def _severity_for_rule(self, type_, rule):
        if type_ == "security":
            return "high"
        elif type_ == "performance":
            return "medium"
        elif type_ == "style":
            return "low"
        else:
            return "medium"

    def _check_cfg_issues(self, file_path):
        """Simple CFG-based checks for JavaScript code"""
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
