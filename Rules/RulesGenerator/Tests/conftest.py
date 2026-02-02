"""
Pytest configuration for RulesGenerator tests.

This file is automatically loaded by pytest and sets up the Python path
so that tests can import from the src directory.
"""
import sys
import os

# Add RulesGenerator directory to Python path (parent of Tests)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

