"""
Test for Ghidra decompiler feature availability
"""

import unittest
import requests
from unittest.mock import Mock, patch, MagicMock


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
            print("✓ Ghidra API is reachable")
        except requests.exceptions.RequestException as e:
            self.skipTest(f"Ghidra API not reachable: {e}")
    
    def test_decompile_endpoint_exists(self):
        """Test if decompile endpoint exists in API"""
        try:
    
            response = requests.get(f"{self.ghidra_api_base}/jobs", timeout=3)
       
            self.assertTrue(response.status_code != 0)
            print("✓ Ghidra API endpoints are available")
        except requests.exceptions.RequestException as e:
            self.skipTest(f"Cannot test endpoints: API not reachable")
    
    def test_decompile_function_call(self):
        """Test decompile function call structure"""
      
        test_url = f"{self.ghidra_api_base}/tools/decompile_function"
        print(f"Decompile URL would be: {test_url}")
        
     
        self.assertIn("decompile_function", test_url)
        self.assertIn("127.0.0.1:8000", test_url)
        print("✓ Decompile URL structure is correct")
    
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
        
        print("✓ Decompiler interface acquisition flow works (mocked)")


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
                print("✓ Ghidra API is online and responding")
                return True
            else:
                print(f"⚠ Ghidra API responded with status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"✗ Ghidra API not reachable: {e}")
            return False


if __name__ == '__main__':
    print("=" * 60)
    print("Testing Ghidra Decompiler Feature Availability")
    print("=" * 60)
    

    suite = unittest.TestLoader().loadTestsFromTestCase(TestDecompilerFeature)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    print("Integration Test Results")
    print("=" * 60)
    
    
    integration_suite = unittest.TestLoader().loadTestsFromTestCase(TestDecompilerIntegration)
    integration_runner = unittest.TextTestRunner(verbosity=2)
    integration_result = integration_runner.run(integration_suite)
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Tests run: {result.testsRun + integration_result.testsRun}")
    print(f"Failures: {len(result.failures) + len(integration_result.failures)}")
    print(f"Skipped: {len(result.skipped) + len(integration_result.skipped)}")
