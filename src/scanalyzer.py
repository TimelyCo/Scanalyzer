#!/usr/bin/env python
"""
Scanalyzer: Static Code Analyzer
Main module that orchestrates the code analysis process
"""

import os
import argparse
import sys
import time

from utils.config import load_config
from analyzers.python_analyzer import PythonAnalyzer
from analyzers.java_analyzer import JavaAnalyzer
from analyzers.js_analyzer import JavaScriptAnalyzer
from analyzers.regex_analyzer import RegexAnalyzer
from reports.report_generator import generate_report


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Scanalyzer: Static Code Analyzer")
    parser.add_argument("path", help="Path to the file or directory to analyze")
    parser.add_argument("--language", "-l", default="auto", 
                        help="Programming language of the source code (auto, python, c++, java, javascript)")
    parser.add_argument("--output", "-o", default="terminal", 
                        help="Output format (terminal, html, json)")
    parser.add_argument("--rules", "-r", default="all", 
                        help="Rules to check (all, security, performance, style)")
    parser.add_argument("--config", "-c", 
                        help="Path to configuration file")
    parser.add_argument("--use-regex", action="store_true",
                        help="Enable regex-based analysis")
    return parser.parse_args()


def detect_language(file_path):
    """Detect the programming language based on file extension"""
    extension = os.path.splitext(file_path)[1].lower()
    
    if extension == ".py":
        return "python"
    elif extension in [".c", ".cpp", ".cc", ".h", ".hpp"]:
        return "c++"
    elif extension == ".java":
        return "java"
    elif extension == ".js":
        return "javascript"
    else:
        return "unknown"


def analyze_file(file_path, language, rules, config, use_regex=False):
    """Analyze a single file"""
    all_issues = []
    
    if language == "auto":
        language = detect_language(file_path)
    
    # Run language-specific analyzer
    if language == "python":
        analyzer = PythonAnalyzer(rules, config)
        all_issues.extend(analyzer.analyze(file_path))
    elif language == "java":
        analyzer = JavaAnalyzer(rules, config)
        all_issues.extend(analyzer.analyze(file_path))
    elif language == "javascript":
        analyzer = JavaScriptAnalyzer(rules, config)
        all_issues.extend(analyzer.analyze(file_path))
    elif language == "c++":
        print(f"C++ analysis not implemented yet for {file_path}")
    else:
        print(f"Unsupported language for {file_path}")
    
    # Run regex analyzer if enabled
    if use_regex:
        regex_analyzer = RegexAnalyzer(rules, config)
        regex_issues = regex_analyzer.analyze_file(file_path)
        all_issues.extend(regex_issues)
    
    return all_issues


def analyze_directory(directory_path, language, rules, config, use_regex=False):
    """Recursively analyze all files in a directory"""
    all_issues = []
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            
            file_language = detect_language(file_path)
            if file_language == "unknown":
                continue
                
            if language != "auto" and file_language != language:
                continue
                
            file_issues = analyze_file(file_path, file_language, rules, config, use_regex)
            all_issues.extend(file_issues)
    
    return all_issues


def main():
    """Main entry point of the program"""
    start_time = time.time()
    args = parse_arguments()
    
    # Load configuration
    config = load_config(args.config) if args.config else {}
    
    # Analyze file or directory
    if os.path.isfile(args.path):
        issues = analyze_file(args.path, args.language, args.rules, config, args.use_regex)
    elif os.path.isdir(args.path):
        issues = analyze_directory(args.path, args.language, args.rules, config, args.use_regex)
    else:
        print(f"Error: {args.path} is not a valid file or directory")
        sys.exit(1)
    
    # Generate report
    generate_report(issues, args.output)
    
    # Print summary
    end_time = time.time()
    print(f"\nAnalysis completed in {end_time - start_time:.2f} seconds.")
    print(f"Found {len(issues)} issues.")


if __name__ == "__main__":
    main()
