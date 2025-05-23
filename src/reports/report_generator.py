"""
Report generator for Scanalyzer
"""

import json
import os
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for colored terminal output
init()

def generate_terminal_report(issues):
    """Generate a colored terminal report"""
    if not issues:
        print(f"{Fore.GREEN}No issues found!{Style.RESET_ALL}")
        return
    
    # Group issues by file
    issues_by_file = {}
    for issue in issues:
        file_path = issue.get('file', 'unknown')
        if file_path not in issues_by_file:
            issues_by_file[file_path] = []
        issues_by_file[file_path].append(issue)
    
    # Print issues by file
    for file_path, file_issues in issues_by_file.items():
        print(f"\n{Fore.CYAN}File: {file_path}{Style.RESET_ALL}")
        print("-" * 80)
        
        # Sort issues by line number
        file_issues.sort(key=lambda x: x.get('line', 0))
        
        for issue in file_issues:
            severity = issue.get('severity', 'low')
            if severity == 'high':
                severity_color = Fore.RED
            elif severity == 'medium':
                severity_color = Fore.YELLOW
            else:
                severity_color = Fore.GREEN
            
            print(f"{severity_color}[{severity.upper()}]{Style.RESET_ALL} "
                  f"Line {issue.get('line', '?')}: {issue.get('message', 'Unknown issue')}")
            
            if 'rule' in issue:
                print(f"  Rule: {issue['rule']}")
            
            print()

def generate_html_report(issues):
    """Generate an HTML report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"scanalyzer_report_{timestamp}.html"
    
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scanalyzer Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            .summary { margin-bottom: 20px; }
            .file { margin-bottom: 30px; border: 1px solid #ddd; padding: 10px; border-radius: 5px; }
            .file-header { background: #f5f5f5; padding: 10px; margin: -10px -10px 10px; border-radius: 5px 5px 0 0; }
            .issue { margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #eee; }
            .high { color: #d9534f; }
            .medium { color: #f0ad4e; }
            .low { color: #5cb85c; }
            .timestamp { color: #777; font-size: 0.9em; }
        </style>
    </head>
    <body>
        <h1>Scanalyzer Report</h1>
        <div class="timestamp">Generated on """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</div>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>Total issues found: """ + str(len(issues)) + """</p>
        </div>
    """
    
    # Group issues by file
    issues_by_file = {}
    for issue in issues:
        file_path = issue.get('file', 'unknown')
        if file_path not in issues_by_file:
            issues_by_file[file_path] = []
        issues_by_file[file_path].append(issue)
    
    # Add issues by file
    for file_path, file_issues in issues_by_file.items():
        html_content += f"""
        <div class="file">
            <div class="file-header">
                <h3>File: {file_path}</h3>
            </div>
        """
        
        # Sort issues by line number
        file_issues.sort(key=lambda x: x.get('line', 0))
        
        for issue in file_issues:
            severity = issue.get('severity', 'low')
            
            html_content += f"""
            <div class="issue">
                <p><span class="{severity}">[{severity.upper()}]</span> Line {issue.get('line', '?')}: {issue.get('message', 'Unknown issue')}</p>
            """
            
            if 'rule' in issue:
                html_content += f"""<p>Rule: {issue['rule']}</p>"""
            
            html_content += """</div>"""
        
        html_content += """</div>"""
    
    html_content += """
    </body>
    </html>
    """
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {os.path.abspath(output_file)}")

def generate_json_report(issues):
    """Generate a detailed JSON report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"scanalyzer_report_{timestamp}.json"
    
    # Group issues by file and severity
    issues_by_file = {}
    severity_counts = {'high': 0, 'medium': 0, 'low': 0}
    
    for issue in issues:
        file_path = issue.get('file', 'unknown')
        severity = issue.get('severity', 'low')
        
        # Update severity counts
        severity_counts[severity] += 1
        
        if file_path not in issues_by_file:
            issues_by_file[file_path] = {
                'total_issues': 0,
                'severity_counts': {'high': 0, 'medium': 0, 'low': 0},
                'issues': []
            }
        
        issues_by_file[file_path]['total_issues'] += 1
        issues_by_file[file_path]['severity_counts'][severity] += 1
        issues_by_file[file_path]['issues'].append(issue)
    
    # Create the report structure
    report = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "tool_version": "1.0.0",
            "analysis_duration": 0,  # This should be set by the main program
            "total_files_analyzed": len(issues_by_file),
            "total_issues": len(issues)
        },
        "summary": {
            "severity_distribution": severity_counts,
            "issue_types": {
                "security": sum(1 for i in issues if i.get('type') == 'security'),
                "performance": sum(1 for i in issues if i.get('type') == 'performance'),
                "style": sum(1 for i in issues if i.get('type') == 'style'),
                "error": sum(1 for i in issues if i.get('type') == 'error')
            }
        },
        "files": {
            file_path: {
                "total_issues": data['total_issues'],
                "severity_distribution": data['severity_counts'],
                "issues": sorted(data['issues'], key=lambda x: x.get('line', 0))
            }
            for file_path, data in issues_by_file.items()
        },
        "recommendations": {
            "high_priority": [
                "Fix all high severity issues first",
                "Address security vulnerabilities immediately",
                "Review and fix critical performance issues"
            ],
            "medium_priority": [
                "Address medium severity issues",
                "Improve code quality and maintainability",
                "Optimize performance bottlenecks"
            ],
            "low_priority": [
                "Fix style and convention issues",
                "Improve code documentation",
                "Enhance code readability"
            ]
        }
    }
    
    # Write the report to file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    print(f"JSON report generated: {os.path.abspath(output_file)}")

def generate_report(issues, output_format="terminal"):
    """Generate a report in the specified format"""
    if output_format == "terminal":
        generate_terminal_report(issues)
    elif output_format == "html":
        generate_html_report(issues)
    elif output_format == "json":
        generate_json_report(issues)
    else:
        print(f"Unsupported output format: {output_format}")
        generate_terminal_report(issues)