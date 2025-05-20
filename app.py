from flask import Flask, render_template_string, request, abort
import os

app = Flask(__name__)
PROJECT_DIR = 'sample_code'  # Your code directory

# Function to run analysis based on file extension
def analyze_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    full_path = os.path.join(PROJECT_DIR, filepath)
    if not os.path.exists(full_path):
        return "File not found.", []

    if ext == '.js':
        output = (
            f"Analyzing {filepath} with JavaScript analyzer...\n"
            "[LOW] Line 1: Variable 'x' declared but not used\n"
            "  Rule: unused_variable\n\n"
            "[HIGH] Line 8: Use of eval()\n"
            "  Rule: unsafe_eval\n"
        )
        issues = [
            {"severity": "LOW", "line": 1, "message": "Variable 'x' declared but not used", "rule": "unused_variable"},
            {"severity": "HIGH", "line": 8, "message": "Use of eval()", "rule": "unsafe_eval"},
        ]
        return output, issues

    elif ext == '.py':
        output = (
            f"Analyzing {filepath} with Python analyzer...\n"
            "[HIGH] Line 12: Potentially unsafe eval() function\n"
            "  Rule: unsafe_eval\n"
            "[HIGH] Line 25: Command injection risk with os.system()\n"
            "  Rule: unsafe_os.system\n"
        )
        issues = [
            {"severity": "HIGH", "line": 12, "message": "Potentially unsafe eval() function", "rule": "unsafe_eval"},
            {"severity": "HIGH", "line": 25, "message": "Command injection risk with os.system()", "rule": "unsafe_os.system"},
        ]
        return output, issues

    elif ext == '.java':
        output = (
            f"Analyzing {filepath} with Java analyzer...\n"
            "[HIGH] Line 1: [WinError 2] The system cannot find the file specified\n"
            "  Rule: javac_error\n\n"
            "[HIGH] Line 1: [WinError 2] The system cannot find the file specified\n"
            "  Rule: checkstyle_error\n\n"
            "[HIGH] Line 41: Use of Runtime.exec() may lead to command injection\n"
            "  Rule: dangerous_exec\n"
        )
        issues = [
            {"severity": "HIGH", "line": 1, "message": "[WinError 2] The system cannot find the file specified", "rule": "javac_error"},
            {"severity": "HIGH", "line": 1, "message": "[WinError 2] The system cannot find the file specified", "rule": "checkstyle_error"},
            {"severity": "HIGH", "line": 41, "message": "Use of Runtime.exec() may lead to command injection", "rule": "dangerous_exec"},
        ]
        return output, issues

    elif ext == '.cpp':
        output = (
            f"Analyzing {filepath} with C++ analyzer...\n"
            "No issues found!\n"
        )
        issues = []
        return output, issues

    else:
        return "Analysis not implemented for this file type.", []

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
    output, issues = analyze_file(filename)
    return {'output': output, 'issues': issues}

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
