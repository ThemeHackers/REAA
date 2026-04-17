#!/usr/bin/env python3
"""
Test Runner Script
Runs all unit tests for the AI Reverse Engineering system
"""

import unittest
import sys
import os
from rich.console import Console
from rich.panel import Panel

console = Console()

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
    console.print(Panel(
        "[bold cyan]Running Unit Tests for AI Reverse Engineering System[/bold cyan]",
        title="[bold]REAA Test Runner[/bold]",
        border_style="cyan"
    ))
    console.print()

    exit_code = run_tests()

    console.print()
    console.print(Panel(
        "[bold green]All tests passed![/bold green]" if exit_code == 0 else "[bold red]Some tests failed![/bold red]",
        title="[bold]Test Result[/bold]",
        border_style="green" if exit_code == 0 else "red"
    ))

    sys.exit(exit_code)
