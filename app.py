from flask import Flask, render_template_string, request, abort
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from scanalyzer import analyze_file as real_analyze_file, detect_language
from utils.config import load_config

app = Flask(__name__)
PROJECT_DIR = 'sample_code'  # Your code directory

# Function to run analysis based on file extension
def analyze_file(filepath):
    print(f"DEBUG: Received filename from frontend: {filepath}")
    full_path = os.path.join(PROJECT_DIR, filepath)
    print(f"DEBUG: Full path to analyze: {full_path}")
    if not os.path.exists(full_path):
        print("DEBUG: File not found.")
        return "File not found.", []

    # Detect language
    language = detect_language(full_path)
    print(f"DEBUG: Detected language: {language}")
    config = load_config(None)
    rules = "all"  # or "security", or get from user input

    # Run the real analyzer
    issues = real_analyze_file(full_path, language, rules, config, use_regex=False)
    print(f"DEBUG: Raw issues from analyzer: {issues}")

    # Format output for display
    output_lines = [f"Analyzing {filepath} with {language.capitalize()} analyzer..."]
    formatted_issues = []
    for issue in issues:
        sev = issue.get("severity", "LOW").upper()
        line = issue.get("line", "?")
        msg = issue.get("message", "")
        rule = issue.get("rule", "")
        output_lines.append(f"[{sev}] Line {line}: {msg}\n  Rule: {rule}\n")
        # Ensure the frontend gets the right format
        formatted_issues.append({
            "severity": sev,
            "line": line,
            "message": msg,
            "rule": rule
        })

    output = "\n".join(output_lines)
    print(f"DEBUG: Output sent to frontend: {output}")
    print(f"DEBUG: Formatted issues sent to frontend: {formatted_issues}")
    return output, formatted_issues

@app.route('/')
def index():
    files = sorted(set(f for f in os.listdir(PROJECT_DIR)
                       if os.path.isfile(os.path.join(PROJECT_DIR, f))))
    counts = {}
    for f in files:
        ext = os.path.splitext(f)[1].lower()
        lang = {'.js': 'JavaScript', '.py': 'Python', '.java': 'Java', '.cpp': 'C++'}.get(ext, 'Other')
        counts[lang] = counts.get(lang, 0) + 1

    logs = [{"file": f"sample_code/{f}", "issues": [], "time": "0.01s", "issues_count": 2} for f in files[:5]]

    return render_template_string(TEMPLATE, counts=counts, recent_files=files[:5], logs=logs)

@app.route('/analyze', methods=['POST'])
def analyze():
    filename = request.json.get('filename')
    print(f"DEBUG: /analyze called with filename: {filename}")
    output, issues = analyze_file(filename)
    print(f"DEBUG: /analyze returning output: {output}")
    print(f"DEBUG: /analyze returning issues: {issues}")
    return {'output': output, 'issues': issues}

@app.route('/test_issue')
def test_issue():
    # For frontend testing: always returns a test issue
    return {'output': 'Test', 'issues': [
        {"severity": "HIGH", "line": 1, "message": "Test issue", "rule": "test_rule"}
    ]}

@app.route('/view/<path:filename>')
def view_file(filename):
    safe_path = os.path.normpath(os.path.join(PROJECT_DIR, filename))
    if not os.path.abspath(safe_path).startswith(os.path.abspath(PROJECT_DIR)):
        abort(403)
    if not os.path.isfile(safe_path):
        return f"\u26a0\ufe0f Error: {filename} not found on server.", 404
    with open(safe_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Scanalyzer Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #2c3e50;
        }
        ul {
            list-style: none;
            padding: 0;
        }
        li a {
            text-decoration: none;
            color: #2980b9;
            font-weight: bold;
            display: block;
            padding: 8px;
            border-radius: 6px;
            transition: 0.3s;
        }
        li a:hover {
            background-color: #dfe6e9;
        }
        pre {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
        }
        .issue {
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
        }
        .HIGH {
            background-color: #f8d7da;
            color: #721c24;
        }
        .LOW {
            background-color: #d4edda;
            color: #155724;
        }
    </style>
    <script>
    async function analyzeFile(filename) {
        document.getElementById('output').textContent = 'Analyzing...';
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename })
        });
        const data = await response.json();
        document.getElementById('output').textContent = data.output;

        const issuesDiv = document.getElementById('issues');
        issuesDiv.innerHTML = '';
        data.issues.forEach(issue => {
            const el = document.createElement('div');
            el.className = `issue ${issue.severity}`;
            el.textContent = `[${issue.severity}] Line ${issue.line}: ${issue.message} (Rule: ${issue.rule})`;
            issuesDiv.appendChild(el);
        });
    }
    </script>
</head>
<body>
    <h1>Scanalyzer Dashboard</h1>
    <h3>Files</h3>
    <ul>
        {% for file in recent_files %}
        <li><a href="#" onclick="analyzeFile('{{ file }}')">{{ file }}</a></li>
        {% endfor %}
    </ul>
    <h3>Analysis Output</h3>
    <pre id="output">Click a file to start analysis.</pre>
    <h3>Issues</h3>
    <div id="issues"></div>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True)
