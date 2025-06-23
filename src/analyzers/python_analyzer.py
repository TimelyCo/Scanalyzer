"""
Python code analyzer that detects common issues in Python code
"""

import ast
import os
import astroid
from pylint import lint
from pylint.reporters.text import TextReporter
import io
from .cfg_builder import CFGBuilder
from .cfg_analyzer import CFGAnalyzer

class PythonAnalyzer:
    """Analyzer for Python source code"""
    
    def __init__(self, rules="all", config=None):
        """Initialize the analyzer with rules and configuration"""
        self.rules = rules
        self.config = config or {}
        
    def _parse_ast(self, file_path):
        """Parse Python file into an AST"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                source = file.read()
            return ast.parse(source, filename=file_path)
        except SyntaxError as e:
            return [{'type': 'error', 
                    'rule': 'syntax_error', 
                    'message': f'Syntax error: {str(e)}',
                    'line': e.lineno, 
                    'column': e.offset, 
                    'severity': 'high',
                    'file': file_path}]
        except Exception as e:
            return [{'type': 'error', 
                    'rule': 'file_error', 
                    'message': f'Error parsing file: {str(e)}',
                    'line': 1, 
                    'column': 1, 
                    'severity': 'high',
                    'file': file_path}]
    
    def _run_pylint(self, file_path):
        """Run Pylint on the file and capture results"""
        issues = []
        
        # Create a string IO to capture pylint output
        output = io.StringIO()
        reporter = TextReporter(output)
        
        # Configure pylint arguments
        args = [
            '--disable=all',  # Disable all checks by default
            '--enable=E,F,W',  # Enable errors, fatal errors, and warnings
            '--output-format=text',
            file_path
        ]
        
        # Add specific rule categories if needed
        if self.rules == "security":
            args.append('--enable=security')
        elif self.rules == "performance":
            args.append('--enable=performance')
        elif self.rules == "style":
            args.append('--enable=convention')
        
        # Run pylint
        try:
            lint.Run(args, reporter=reporter, exit=False)
            output_str = output.getvalue()
            
            # Parse the output and convert to our issue format
            for line in output_str.splitlines():
                if ":" in line and line[0].isalpha():
                    continue
                    
                parts = line.split(":")
                if len(parts) >= 3:
                    try:
                        line_num = int(parts[1].strip())
                        message = ":".join(parts[2:]).strip()
                        
                        # Extract pylint code and severity from message
                        if '(' in message and ')' in message:
                            code_part = message.split('(')[1].split(')')[0]
                            severity = 'medium'
                            
                            if code_part.startswith('E'):
                                severity = 'high'
                            elif code_part.startswith('W'):
                                severity = 'medium'
                            elif code_part.startswith('C'):
                                severity = 'low'
                            
                            issues.append({
                                'type': 'pylint',
                                'rule': code_part,
                                'message': message,
                                'line': line_num,
                                'column': 0,  # Pylint doesn't always provide column info
                                'severity': severity,
                                'file': file_path
                            })
                    except (ValueError, IndexError):
                        continue
        except Exception as e:
            issues.append({
                'type': 'error',
                'rule': 'pylint_error',
                'message': f'Error running Pylint: {str(e)}',
                'line': 1,
                'column': 1,
                'severity': 'medium',
                'file': file_path
            })
        
        return issues
    
    def _check_security_issues(self, tree, file_path):
        """Check for security issues using AST"""
        issues = []
        
        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self, file_path, issues_list):
                self.file_path = file_path
                self.issues = issues_list
            
            def visit_Call(self, node):
                # Check for potentially dangerous functions
                dangerous_functions = {
                    'eval': 'Potentially unsafe eval() function',
                    'exec': 'Potentially unsafe exec() function',
                    'os.system': 'Command injection risk with os.system()',
                    'subprocess.call': 'Command injection risk with subprocess',
                    'pickle.load': 'Deserialization vulnerability with pickle',
                    'marshal.load': 'Deserialization vulnerability with marshal',
                }
                
                # Check if it's a simple name function call
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in dangerous_functions:
                        self.issues.append({
                            'type': 'security',
                            'rule': f'unsafe_{func_name}',
                            'message': dangerous_functions[func_name],
                            'line': node.lineno,
                            'column': node.col_offset,
                            'severity': 'high',
                            'file': self.file_path
                        })
                
                # Check if it's an attribute call
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        call_path = f"{node.func.value.id}.{node.func.attr}"
                        if call_path in dangerous_functions:
                            self.issues.append({
                                'type': 'security',
                                'rule': f'unsafe_{call_path}',
                                'message': dangerous_functions[call_path],
                                'line': node.lineno,
                                'column': node.col_offset,
                                'severity': 'high',
                                'file': self.file_path
                            })
                
                # Continue visiting child nodes
                self.generic_visit(node)
        
        # Parse the AST and visit all nodes
        if isinstance(tree, list):  # Error occurred during parsing
            return tree
        
        visitor = SecurityVisitor(file_path, issues)
        visitor.visit(tree)
        return issues
    
    def _check_performance_issues(self, tree, file_path):
        """Check for performance issues using AST"""
        issues = []
        
        class PerformanceVisitor(ast.NodeVisitor):
            def __init__(self, file_path, issues_list):
                self.file_path = file_path
                self.issues = issues_list
                self.in_loop = False
                self.loop_stack = []
            
            def visit_For(self, node):
                self.loop_stack.append(node)
                self.generic_visit(node)
                self.loop_stack.pop()
            
            def visit_While(self, node):
                self.loop_stack.append(node)
                self.generic_visit(node)
                self.loop_stack.pop()
            
            def visit_ListComp(self, node):
                # Check for nested list comprehensions
                for generator in node.generators:
                    if isinstance(generator.iter, ast.ListComp):
                        self.issues.append({
                            'type': 'performance',
                            'rule': 'nested_list_comp',
                            'message': 'Nested list comprehension could cause performance issues',
                            'line': node.lineno,
                            'column': node.col_offset,
                            'severity': 'medium',
                            'file': self.file_path
                        })
                self.generic_visit(node)
            
            def visit_Call(self, node):
                # Check for function calls in loops
                if self.loop_stack and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        # Check for common expensive operations in loops
                        if node.func.attr in ['copy', 'deepcopy', 'sort']:
                            self.issues.append({
                                'type': 'performance',
                                'rule': 'expensive_operation_in_loop',
                                'message': f'Expensive operation {node.func.attr}() called inside a loop',
                                'line': node.lineno,
                                'column': node.col_offset,
                                'severity': 'medium',
                                'file': self.file_path
                            })
                self.generic_visit(node)
        
        # Parse the AST and visit all nodes
        if isinstance(tree, list):  # Error occurred during parsing
            return tree
        
        visitor = PerformanceVisitor(file_path, issues)
        visitor.visit(tree)
        return issues
    
    def analyze(self, file_path):
        """Analyze Python file and return issues"""
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
        
        # Parse the AST
        ast_tree = self._parse_ast(file_path)
        
        # CFG Analysis (only if AST is valid)
        if not isinstance(ast_tree, list):
            cfg_builder = CFGBuilder()
            cfg = cfg_builder.build_cfg(ast_tree)
            cfg_analyzer = CFGAnalyzer()
            cfg_findings = cfg_analyzer.analyze(cfg)
            for rule, nodes in cfg_findings.items():
                for node in nodes:
                    lineno = getattr(node.ast_node, 'lineno', 1)
                    issues.append({
                        'type': 'cfg',
                        'rule': rule,
                        'message': f'CFG {rule.replace("_", " ")}: Node {getattr(node, "name", str(node))}',
                        'line': lineno,
                        'column': getattr(node.ast_node, 'col_offset', 0),
                        'severity': 'medium',
                        'file': file_path
                    })
        
        # Run different checks based on rules
        if self.rules in ["all", "security"]:
            security_issues = self._check_security_issues(ast_tree, file_path)
            issues.extend(security_issues)
        
        if self.rules in ["all", "performance"]:
            performance_issues = self._check_performance_issues(ast_tree, file_path)
            issues.extend(performance_issues)
        
        # Run pylint for additional checks
        pylint_issues = self._run_pylint(file_path)
        issues.extend(pylint_issues)
        
        return issues