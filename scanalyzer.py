#!/usr/bin/env python
"""
Entry point script for Scanalyzer
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import the main module
from src.scanalyzer import main

if __name__ == "__main__":
    main()