#!/usr/bin/env python3
"""
Test Runner Script
Runs all unit tests for the AI Reverse Engineering system
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_tests():
    """Run all unit tests"""
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(os.path.abspath(__file__))
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    print("=" * 70)
    print("Running Unit Tests for AI Reverse Engineering System")
    print("=" * 70)
    print()
    
    exit_code = run_tests()
    
    print()
    print("=" * 70)
    if exit_code == 0:
        print("All tests passed!")
    else:
        print("Some tests failed!")
    print("=" * 70)
    
    sys.exit(exit_code)
