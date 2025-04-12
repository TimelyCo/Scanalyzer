"""
Configuration utilities for Scanalyzer
"""

import json
import os
import sys

def load_config(config_path):
    """Load configuration from a JSON file"""
    if not os.path.exists(config_path):
        print(f"Error: Configuration file '{config_path}' not found.")
        sys.exit(1)
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in configuration file '{config_path}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading configuration: {str(e)}")
        sys.exit(1)

def get_default_config():
    """Return default configuration"""
    return {
        "severity_levels": {
            "high": True,
            "medium": True,
            "low": True
        },
        "rules": {
            "security": True,
            "performance": True,
            "style": True
        },
        "ignore_patterns": [
            "**/venv/**",
            "**/__pycache__/**",
            "**/node_modules/**"
        ]
    }