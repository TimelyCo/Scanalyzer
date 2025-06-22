#!/usr/bin/env python
"""
Scanalyzer: Static Code Analyzer
Main module that orchestrates the code analysis process
"""

import os
import argparse
import sys
import time
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import smtplib
from email.mime.text import MIMEText

from utils.config import load_config
from analyzers.python_analyzer import PythonAnalyzer
from analyzers.java_analyzer import JavaAnalyzer
from analyzers.js_analyzer import JavaScriptAnalyzer
from analyzers.cpp_analyzer import CppAnalyzer
from analyzers.regex_analyzer import RegexAnalyzer
from reports.report_generator import generate_report

CACHE_DIR = 'cache'  # Directory to store cached analysis results
os.makedirs(CACHE_DIR, exist_ok=True)

# --- Caching Utilities ---
def file_hash(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

def analyze_file_with_cache(file_path, language, rules, config, use_regex=False):
    h = file_hash(file_path)
    cache_file = os.path.join(CACHE_DIR, h + '.json')
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            return json.load(f)
    result = analyze_file(file_path, language, rules, config, use_regex)
    with open(cache_file, 'w') as f:
        json.dump(result, f)
    return result

# --- Regex Optimization Note ---
# For best performance, analyzers should use re.compile for regex patterns (see analyzers/*_analyzer.py)

# --- Email Notification Utilities ---
def send_email_notification(subject, body, to_email, from_email, smtp_server, smtp_port, smtp_user, smtp_pass):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_email, [to_email], msg.as_string())
        print(f"Email notification sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email notification: {e}")

def notify_if_issues_email(issues, email_config):
    high_issues = [i for i in issues if i.get('severity', '').lower() == 'high']
    if high_issues:
        subject = "Scanalyzer: High Severity Issues Detected"
        body = f"Scanalyzer found {len(high_issues)} high severity issues!\n\nDetails:\n"
        for issue in high_issues[:5]:
            body += f"- {issue.get('file', '')} (Line {issue.get('line', '?')}): {issue.get('message', '')}\n"
        if len(high_issues) > 5:
            body += f"...and {len(high_issues) - 5} more.\n"
        send_email_notification(subject, body, **email_config)

# --- Main Analyzer Functions ---
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
        analyzer = CppAnalyzer(rules, config)
        all_issues.extend(analyzer.analyze(file_path))
    else:
        print(f"Unsupported language for {file_path}")
    
    # Run regex analyzer if enabled
    if use_regex:
        regex_analyzer = RegexAnalyzer(rules, config)
        regex_issues = regex_analyzer.analyze_file(file_path)
        all_issues.extend(regex_issues)
    
    return all_issues


def analyze_directory_parallel(directory_path, language, rules, config, use_regex=False):
    """Analyze all files in a directory in parallel, with caching and incremental analysis."""
    all_files = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_language = detect_language(file_path)
            if file_language == "unknown":
                continue
            if language != "auto" and file_language != language:
                continue
            # Incremental analysis: only analyze if not in cache
            h = file_hash(file_path)
            cache_file = os.path.join(CACHE_DIR, h + '.json')
            if not os.path.exists(cache_file):
                all_files.append((file_path, file_language))
    all_issues = []
    # Analyze in parallel
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(analyze_file_with_cache, f, lang, rules, config, use_regex) for f, lang in all_files]
        for future in as_completed(futures):
            all_issues.extend(future.result())
    # Add cached results for files not analyzed this run
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_language = detect_language(file_path)
            if file_language == "unknown":
                continue
            if language != "auto" and file_language != language:
                continue
            h = file_hash(file_path)
            cache_file = os.path.join(CACHE_DIR, h + '.json')
            if os.path.exists(cache_file):
                with open(cache_file) as f:
                    all_issues.extend(json.load(f))
    return all_issues


def main():
    """Main entry point of the program"""
    start_time = time.time()
    args = parse_arguments()
    
    # Load configuration
    config = load_config(args.config) if args.config else {}
    
    # Analyze file or directory
    if os.path.isfile(args.path):
        issues = analyze_file_with_cache(args.path, args.language, args.rules, config, args.use_regex)
    elif os.path.isdir(args.path):
        issues = analyze_directory_parallel(args.path, args.language, args.rules, config, args.use_regex)
    else:
        print(f"Error: {args.path} is not a valid file or directory")
        sys.exit(1)
    
    # Generate report
    generate_report(issues, args.output)
    
    # --- Email notification config (fill in your details) ---
    email_config = {
        'to_email': 'anmolraturi246@gmail.com',
        'from_email': 'anmolraturi444@outlook.com',
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 465,
        'smtp_user': 'anmolraturi444@outlook.com',
        'smtp_pass': 'Anmol123)(*',
    }
    notify_if_issues_email(issues, email_config)
    
    # Print summary
    end_time = time.time()
    print(f"\nAnalysis completed in {end_time - start_time:.2f} seconds.")
    print(f"Found {len(issues)} issues.")


if __name__ == "__main__":
    main()
