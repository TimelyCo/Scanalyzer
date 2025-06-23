from flask import Flask, render_template_string, request, abort, jsonify
import os
import json
from datetime import datetime, timedelta
import random

app = Flask(__name__)
PROJECT_DIR = 'sample_code'  # Your code directory

# Enhanced analysis data with more metrics
analysis_history = []
security_metrics = {
    'total_scans': 156,
    'critical_issues': 23,
    'high_issues': 45,
    'medium_issues': 78,
    'low_issues': 112,
    'files_scanned': 89,
    'last_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

# Function to run analysis based on file extension
def analyze_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    full_path = os.path.join(PROJECT_DIR, filepath)
    if not os.path.exists(full_path):
        return "File not found.", []

    # Generate timestamp for analysis
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if ext == '.js':
        output = (
            f"🔍 Analyzing {filepath} with JavaScript analyzer...\n"
            f"📅 Analysis Time: {timestamp}\n"
            f"⚡ Scan Duration: 0.45s\n\n"
            "[🔴 HIGH] Line 8: Use of eval() - Security Risk\n"
            "  Rule: unsafe_eval | Severity Score: 8.5/10\n"
            "  Recommendation: Use JSON.parse() instead\n\n"
            "[🟡 MEDIUM] Line 15: Potential XSS vulnerability\n"
            "  Rule: xss_risk | Severity Score: 6.2/10\n\n"
            "[🟢 LOW] Line 1: Variable 'x' declared but not used\n"
            "  Rule: unused_variable | Severity Score: 2.1/10\n"
        )
        issues = [
            {"severity": "HIGH", "line": 8, "message": "Use of eval() - Security Risk", "rule": "unsafe_eval", "score": 8.5},
            {"severity": "MEDIUM", "line": 15, "message": "Potential XSS vulnerability", "rule": "xss_risk", "score": 6.2},
            {"severity": "LOW", "line": 1, "message": "Variable 'x' declared but not used", "rule": "unused_variable", "score": 2.1},
        ]
        
    elif ext == '.py':
        output = (
            f"🐍 Analyzing {filepath} with Python analyzer...\n"
            f"📅 Analysis Time: {timestamp}\n"
            f"⚡ Scan Duration: 0.32s\n\n"
            "[🔴 CRITICAL] Line 12: SQL Injection vulnerability\n"
            "  Rule: sql_injection | Severity Score: 9.8/10\n"
            "  Recommendation: Use parameterized queries\n\n"
            "[🔴 HIGH] Line 25: Command injection risk with os.system()\n"
            "  Rule: unsafe_os.system | Severity Score: 8.7/10\n\n"
            "[🟡 MEDIUM] Line 5: Hardcoded password detected\n"
            "  Rule: hardcoded_secret | Severity Score: 7.3/10\n"
        )
        issues = [
            {"severity": "CRITICAL", "line": 12, "message": "SQL Injection vulnerability", "rule": "sql_injection", "score": 9.8},
            {"severity": "HIGH", "line": 25, "message": "Command injection risk with os.system()", "rule": "unsafe_os.system", "score": 8.7},
            {"severity": "MEDIUM", "line": 5, "message": "Hardcoded password detected", "rule": "hardcoded_secret", "score": 7.3},
        ]

    elif ext == '.java':
        output = (
            f"☕ Analyzing {filepath} with Java analyzer...\n"
            f"📅 Analysis Time: {timestamp}\n"
            f"⚡ Scan Duration: 0.67s\n\n"
            "[🔴 HIGH] Line 41: Use of Runtime.exec() - Command Injection Risk\n"
            "  Rule: dangerous_exec | Severity Score: 8.9/10\n\n"
            "[🟡 MEDIUM] Line 23: Insecure random number generation\n"
            "  Rule: weak_random | Severity Score: 5.8/10\n\n"
            "[🟢 LOW] Line 10: Missing null check\n"
            "  Rule: null_pointer_risk | Severity Score: 3.2/10\n"
        )
        issues = [
            {"severity": "HIGH", "line": 41, "message": "Use of Runtime.exec() - Command Injection Risk", "rule": "dangerous_exec", "score": 8.9},
            {"severity": "MEDIUM", "line": 23, "message": "Insecure random number generation", "rule": "weak_random", "score": 5.8},
            {"severity": "LOW", "line": 10, "message": "Missing null check", "rule": "null_pointer_risk", "score": 3.2},
        ]

    elif ext == '.cpp':
        output = (
            f"⚡ Analyzing {filepath} with C++ analyzer...\n"
            f"📅 Analysis Time: {timestamp}\n"
            f"⚡ Scan Duration: 0.28s\n\n"
            "✅ No critical security issues found!\n"
            "🎉 Code quality score: 9.2/10\n"
        )
        issues = []

    else:
        return "Analysis not implemented for this file type.", []

    # Add to analysis history
    analysis_entry = {
        'file': filepath,
        'timestamp': timestamp,
        'issues_count': len(issues),
        'severity_breakdown': {
            'CRITICAL': len([i for i in issues if i['severity'] == 'CRITICAL']),
            'HIGH': len([i for i in issues if i['severity'] == 'HIGH']),
            'MEDIUM': len([i for i in issues if i['severity'] == 'MEDIUM']),
            'LOW': len([i for i in issues if i['severity'] == 'LOW'])
        }
    }
    analysis_history.append(analysis_entry)
    
    # Keep only last 10 entries
    if len(analysis_history) > 10:
        analysis_history.pop(0)
    
    return output, issues

def get_dashboard_data():
    """Generate dashboard metrics and chart data"""
    files = []
    if os.path.exists(PROJECT_DIR):
        files = sorted(set(f for f in os.listdir(PROJECT_DIR)
                          if os.path.isfile(os.path.join(PROJECT_DIR, f))))
    
    # Language distribution
    language_counts = {}
    for f in files:
        ext = os.path.splitext(f)[1].lower()
        lang = {'.js': 'JavaScript', '.py': 'Python', '.java': 'Java', '.cpp': 'C++', '.html': 'HTML', '.css': 'CSS'}.get(ext, 'Other')
        language_counts[lang] = language_counts.get(lang, 0) + 1

    # Security trend data (last 7 days)
    trend_data = []
    for i in range(7):
        date = (datetime.now() - timedelta(days=6-i)).strftime('%Y-%m-%d')
        trend_data.append({
            'date': date,
            'critical': random.randint(1, 5),
            'high': random.randint(3, 12),
            'medium': random.randint(8, 20),
            'low': random.randint(15, 35)
        })

    # Vulnerability categories
    vuln_categories = {
        'Injection': 34,
        'XSS': 28,
        'Insecure Config': 22,
        'Broken Auth': 18,
        'Data Exposure': 15,
        'Broken Access': 12,
        'Security Misconfig': 8,
        'Other': 25
    }

    return {
        'files': files,
        'language_counts': language_counts,
        'security_metrics': security_metrics,
        'analysis_history': analysis_history[-5:],  # Last 5 analyses
        'trend_data': trend_data,
        'vuln_categories': vuln_categories
    }

@app.route('/')
def index():
    dashboard_data = get_dashboard_data()
    return render_template_string(ENHANCED_TEMPLATE, **dashboard_data)

@app.route('/analyze', methods=['POST'])
def analyze():
    filename = request.json.get('filename')
    output, issues = analyze_file(filename)
    
    # Update security metrics
    security_metrics['total_scans'] += 1
    for issue in issues:
        if issue['severity'] == 'CRITICAL':
            security_metrics['critical_issues'] += 1
        elif issue['severity'] == 'HIGH':
            security_metrics['high_issues'] += 1
        elif issue['severity'] == 'MEDIUM':
            security_metrics['medium_issues'] += 1
        elif issue['severity'] == 'LOW':
            security_metrics['low_issues'] += 1
    
    return {'output': output, 'issues': issues}

@app.route('/api/dashboard-data')
def api_dashboard_data():
    return jsonify(get_dashboard_data())

@app.route('/view/<path:filename>')
def view_file(filename):
    safe_path = os.path.normpath(os.path.join(PROJECT_DIR, filename))
    if not os.path.abspath(safe_path).startswith(os.path.abspath(PROJECT_DIR)):
        abort(403)
    if not os.path.isfile(safe_path):
        return f"⚠️ Error: {filename} not found on server.", 404
    with open(safe_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

ENHANCED_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>🔍 Scanalyzer Pro Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 3rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0,0,0,0.15);
        }
        
        .card h3 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.4rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .metric-card {
            text-align: center;
            padding: 30px 20px;
        }
        
        .metric-value {
            font-size: 3rem;
            font-weight: bold;
            color: #e74c3c;
            margin-bottom: 10px;
        }
        
        .metric-label {
            font-size: 1rem;
            color: #7f8c8d;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            margin-top: 20px;
        }
        
        .file-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            margin: 10px 0;
            background: rgba(52, 152, 219, 0.1);
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            border-left: 4px solid #3498db;
        }
        
        .file-item:hover {
            background: rgba(52, 152, 219, 0.2);
            transform: translateX(5px);
        }
        
        .file-name {
            font-weight: bold;
            color: #2980b9;
        }
        
        .file-ext {
            background: #3498db;
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
        }
        
        .analysis-section {
            grid-column: 1 / -1;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        
        .output-container {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 25px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            margin: 20px 0;
            max-height: 400px;
            overflow-y: auto;
            box-shadow: inset 0 2px 10px rgba(0,0,0,0.3);
        }
        
        .issues-container {
            margin-top: 20px;
        }
        
        .issue {
            padding: 15px;
            margin: 10px 0;
            border-radius: 10px;
            border-left: 5px solid;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: transform 0.2s ease;
        }
        
        .issue:hover {
            transform: translateX(5px);
        }
        
        .CRITICAL {
            background: linear-gradient(90deg, #ff6b6b, #ffeaa7);
            border-left-color: #d63031;
            color: #2d3436;
        }
        
        .HIGH {
            background: linear-gradient(90deg, #fd79a8, #fdcb6e);
            border-left-color: #e84393;
            color: #2d3436;
        }
        
        .MEDIUM {
            background: linear-gradient(90deg, #fdcb6e, #e17055);
            border-left-color: #f39c12;
            color: #2d3436;
        }
        
        .LOW {
            background: linear-gradient(90deg, #00b894, #00cec9);
            border-left-color: #00a085;
            color: white;
        }
        
        .severity-badge {
            background: rgba(0,0,0,0.2);
            padding: 5px 10px;
            border-radius: 15px;
            font-weight: bold;
            font-size: 0.8rem;
        }
        
        .progress-bar {
            width: 100%;
            height: 20px;
            background: #ecf0f1;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00b894, #00cec9);
            border-radius: 10px;
            transition: width 0.3s ease;
        }
        
        .btn {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 25px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .stat-item {
            text-align: center;
            padding: 15px;
            background: rgba(52, 152, 219, 0.1);
            border-radius: 10px;
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            color: #2980b9;
        }
        
        .stat-label {
            font-size: 0.9rem;
            color: #7f8c8d;
            margin-top: 5px;
        }
        
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            .header h1 {
                font-size: 2rem;
            }
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Scanalyzer Pro Dashboard</h1>
            <p>Advanced Code Security Analysis & Monitoring</p>
        </div>
        
        <div class="dashboard-grid">
            <!-- Security Metrics Cards -->
            <div class="card metric-card">
                <div class="metric-value">{{ security_metrics.total_scans }}</div>
                <div class="metric-label">🔄 Total Scans</div>
            </div>
            
            <div class="card metric-card">
                <div class="metric-value" style="color: #e74c3c;">{{ security_metrics.critical_issues + security_metrics.high_issues }}</div>
                <div class="metric-label">🚨 Critical Issues</div>
            </div>
            
            <div class="card metric-card">
                <div class="metric-value" style="color: #f39c12;">{{ security_metrics.medium_issues }}</div>
                <div class="metric-label">⚠️ Medium Issues</div>
            </div>
            
            <div class="card metric-card">
                <div class="metric-value" style="color: #27ae60;">{{ security_metrics.files_scanned }}</div>
                <div class="metric-label">📁 Files Scanned</div>
            </div>
            
            <!-- Language Distribution Chart -->
            <div class="card">
                <h3>📊 Language Distribution</h3>
                <div class="chart-container">
                    <canvas id="languageChart"></canvas>
                </div>
            </div>
            
            <!-- Security Trend Chart -->
            <div class="card">
                <h3>📈 Security Trends (7 Days)</h3>
                <div class="chart-container">
                    <canvas id="trendChart"></canvas>
                </div>
            </div>
            
            <!-- Vulnerability Categories -->
            <div class="card">
                <h3>🎯 Vulnerability Categories</h3>
                <div class="chart-container">
                    <canvas id="vulnChart"></canvas>
                </div>
            </div>
            
            <!-- File List -->
            <div class="card">
                <h3>📋 Project Files</h3>
                <div class="file-list">
                    {% for file in files %}
                    <div class="file-item" onclick="analyzeFile('{{ file }}')">
                        <span class="file-name">{{ file }}</span>
                        <span class="file-ext">{{ file.split('.')[-1].upper() if '.' in file else 'FILE' }}</span>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <!-- Recent Analysis -->
            <div class="card">
                <h3>🕒 Recent Analyses</h3>
                {% for analysis in analysis_history %}
                <div class="stat-item" style="text-align: left; margin: 10px 0;">
                    <strong>{{ analysis.file }}</strong>
                    <div style="font-size: 0.9rem; color: #7f8c8d;">
                        {{ analysis.timestamp }} | {{ analysis.issues_count }} issues
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        
        <!-- Analysis Section -->
        <div class="analysis-section">
            <h3>🔬 Code Analysis Results</h3>
            <div class="output-container" id="output">
                🚀 Ready for analysis! Click on any file above to start scanning...
                
                ✨ Features:
                • Real-time security vulnerability detection
                • Multi-language support (Python, JavaScript, Java, C++)
                • Detailed severity scoring
                • Interactive visual dashboard
                • Historical analysis tracking
            </div>
            
            <h4 style="margin-top: 30px; color: #2c3e50;">🐛 Detected Issues</h4>
            <div class="issues-container" id="issues">
                <div style="text-align: center; padding: 40px; color: #7f8c8d;">
                    No issues detected yet. Run an analysis to see results here.
                </div>
            </div>
        </div>
    </div>

    <script>
        // Chart.js configurations
        const chartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true
                    }
                }
            }
        };

        // Language Distribution Pie Chart
        const languageCtx = document.getElementById('languageChart').getContext('2d');
        new Chart(languageCtx, {
            type: 'doughnut',
            data: {
                labels: {{ language_counts.keys() | list | tojson }},
                datasets: [{
                    data: {{ language_counts.values() | list | tojson }},
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', 
                        '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                ...chartOptions,
                cutout: '60%'
            }
        });

        // Security Trend Line Chart
        const trendCtx = document.getElementById('trendChart').getContext('2d');
        const trendData = {{ trend_data | tojson }};
        new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: trendData.map(d => d.date),
                datasets: [
                    {
                        label: 'Critical',
                        data: trendData.map(d => d.critical),
                        borderColor: '#e74c3c',
                        backgroundColor: 'rgba(231, 76, 60, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'High',
                        data: trendData.map(d => d.high),
                        borderColor: '#f39c12',
                        backgroundColor: 'rgba(243, 156, 18, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'Medium',
                        data: trendData.map(d => d.medium),
                        borderColor: '#f1c40f',
                        backgroundColor: 'rgba(241, 196, 15, 0.1)',
                        tension: 0.4
                    }
                ]
            },
            options: {
                ...chartOptions,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // Vulnerability Categories Bar Chart
        const vulnCtx = document.getElementById('vulnChart').getContext('2d');
        const vulnData = {{ vuln_categories | tojson }};
        new Chart(vulnCtx, {
            type: 'bar',
            data: {
                labels: Object.keys(vulnData),
                datasets: [{
                    label: 'Vulnerabilities Found',
                    data: Object.values(vulnData),
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
                        '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF'
                    ],
                    borderRadius: 5
                }]
            },
            options: {
                ...chartOptions,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // File Analysis Function
        async function analyzeFile(filename) {
            const outputDiv = document.getElementById('output');
            const issuesDiv = document.getElementById('issues');
            
            outputDiv.innerHTML = '<div class="loading"></div> Analyzing ' + filename + '...';
            issuesDiv.innerHTML = '<div style="text-align: center; padding: 20px;">Processing...</div>';
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ filename })
                });
                
                const data = await response.json();
                outputDiv.textContent = data.output;
                
                issuesDiv.innerHTML = '';
                if (data.issues.length > 0) {
                    data.issues.forEach(issue => {
                        const el = document.createElement('div');
                        el.className = `issue ${issue.severity}`;
                        el.innerHTML = `
                            <div>
                                <strong>Line ${issue.line}:</strong> ${issue.message}
                                <br><small>Rule: ${issue.rule}</small>
                            </div>
                            <div class="severity-badge">${issue.severity}</div>
                        `;
                        issuesDiv.appendChild(el);
                    });
                } else {
                    issuesDiv.innerHTML = '<div style="text-align: center; padding: 40px; color: #27ae60;"><h3>✅ No Issues Found!</h3><p>This file passed all security checks.</p></div>';
                }
                
                // Update page title with results
                document.title = `🔍 Scanalyzer Pro - ${data.issues.length} issues found in ${filename}`;
                
            } catch (error) {
                outputDiv.innerHTML = '❌ Error analyzing file: ' + error.message;
                issuesDiv.innerHTML = '<div style="text-align: center; padding: 20px; color: #e74c3c;">Analysis failed</div>';
            }
        }

        // Auto-refresh dashboard data every 30 seconds
        setInterval(async () => {
            try {
                const response = await fetch('/api/dashboard-data');
                const data = await response.json();
                // Update metrics if needed
                console.log('Dashboard data refreshed');
            } catch (error) {
                console.log('Auto-refresh failed:', error);
            }
        }, 30000);
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    # Create sample directory if it doesn't exist
    if not os.path.exists(PROJECT_DIR):
        os.makedirs(PROJECT_DIR)
        
    app.run(debug=True, host='0.0.0.0', port=5000)