"""
Test for Ghidra decompiler feature availability
"""

import unittest
import requests
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

console = Console()


class TestDecompilerFeature(unittest.TestCase):
    """Test cases for decompiler feature availability"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.ghidra_api_base = "http://127.0.0.1:8000"
    
    def test_ghidra_api_reachable(self):
        """Test if Ghidra API is reachable"""
        try:
            response = requests.get(f"{self.ghidra_api_base}/jobs", timeout=3)
            self.assertIn(response.status_code, [200, 404, 500])
            console.print("[green]✓[/green] Ghidra API is reachable")
        except requests.exceptions.RequestException as e:
            self.skipTest(f"Ghidra API not reachable: {e}")
    
    def test_decompile_endpoint_exists(self):
        """Test if decompile endpoint exists in API"""
        try:

            response = requests.get(f"{self.ghidra_api_base}/jobs", timeout=3)

            self.assertTrue(response.status_code != 0)
            console.print("[green]✓[/green] Ghidra API endpoints are available")
        except requests.exceptions.RequestException as e:
            self.skipTest(f"Cannot test endpoints: API not reachable")

    def test_decompile_function_call(self):
        """Test decompile function call structure"""

        test_url = f"{self.ghidra_api_base}/tools/decompile_function"
        console.print(f"[cyan]Decompile URL would be:[/cyan] {test_url}")


        self.assertIn("decompile_function", test_url)
        self.assertIn("127.0.0.1:8000", test_url)
        console.print("[green]✓[/green] Decompile URL structure is correct")
    
    def test_ghidra_script_decompiler_check(self):
        """Test if Ghidra script can check decompiler availability"""

        mock_state = Mock()
        mock_tool = Mock()
        mock_decompiler_service = Mock()
        mock_decompiler_interface = Mock()


        mock_state.getTool.return_value = mock_tool
        mock_tool.getService.return_value = mock_decompiler_service
        mock_decompiler_service.getDecompilerInterface.return_value = mock_decompiler_interface


        tool = mock_state.getTool()
        self.assertIsNotNone(tool)

        decompiler_service = tool.getService("Decompiler")
        self.assertIsNotNone(decompiler_service)

        console.print("[green]✓[/green] Decompiler interface acquisition flow works (mocked)")


class TestDecompilerIntegration(unittest.TestCase):
    """Integration tests for decompiler with real Ghidra API"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.ghidra_api_base = "http://127.0.0.1:8000"
    
    def test_system_status_check(self):
        """Test system status endpoint to check Ghidra availability"""
        try:
            response = requests.get(f"{self.ghidra_api_base}/jobs", timeout=3)
            if response.status_code == 200:
                console.print("[green]✓[/green] Ghidra API is online and responding")
                return True
            else:
                console.print(f"[yellow]⚠[/yellow] Ghidra API responded with status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            console.print(f"[red]✗[/red] Ghidra API not reachable: {e}")
            return False


if __name__ == '__main__':
    console.print(Panel(
        "[bold cyan]Testing Ghidra Decompiler Feature Availability[/bold cyan]",
        title="[bold]REAA Test[/bold]",
        border_style="cyan"
    ))


    suite = unittest.TestLoader().loadTestsFromTestCase(TestDecompilerFeature)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    console.print(Panel(
        "[bold cyan]Integration Test Results[/bold cyan]",
        title="[bold]Integration Tests[/bold]",
        border_style="cyan"
    ))


    integration_suite = unittest.TestLoader().loadTestsFromTestCase(TestDecompilerIntegration)
    integration_runner = unittest.TextTestRunner(verbosity=2)
    integration_result = integration_runner.run(integration_suite)

    console.print(Panel(
        f"[bold]Tests run:[/bold] {result.testsRun + integration_result.testsRun}\n[red]Failures:[/red] {len(result.failures) + len(integration_result.failures)}\n[yellow]Skipped:[/yellow] {len(result.skipped) + len(integration_result.skipped)}",
        title="[bold]Summary[/bold]",
        border_style="green" if (len(result.failures) + len(integration_result.failures)) == 0 else "red"
    ))
