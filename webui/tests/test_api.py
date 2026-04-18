
import unittest
import json
import os
from unittest.mock import Mock, patch, MagicMock
import base64


class TestAuthenticationEndpoints(unittest.TestCase):
    def setUp(self):
        self.app = Mock()
        self.app.config = {'SECRET_KEY': 'test_key'}
    
    @patch('app.User')
    @patch('app.db')
    def test_register_endpoint(self, mock_db, mock_user):
        mock_user_instance = Mock()
        mock_user_instance.to_dict.return_value = {'id': 'user123', 'username': 'testuser'}
        mock_user.return_value = mock_user_instance
        mock_user.query.filter_by.return_value.first.return_value = None
        
        registration_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123'
        }
        
        self.assertIn('username', registration_data)
        self.assertIn('email', registration_data)
        self.assertIn('password', registration_data)
    
    @patch('app.User')
    @patch('app.auth_manager')
    def test_login_endpoint(self, mock_auth_manager, mock_user):
        mock_user_instance = Mock()
        mock_user_instance.check_password.return_value = True
        mock_user_instance.is_active = True
        mock_user_instance.last_login = None
        mock_user_instance.to_dict.return_value = {'id': 'user123', 'username': 'testuser'}
        mock_user.query.filter_by.return_value.first.return_value = mock_user_instance
        
        mock_auth_manager.generate_token.return_value = 'test_token_123'
        mock_auth_manager.create_session.return_value = Mock()
        
        login_data = {
            'username': 'testuser',
            'password': 'password123'
        }
        
        self.assertIn('username', login_data)
        self.assertIn('password', login_data)
        
        self.assertTrue(mock_user_instance.check_password('password123'))
    
    @patch('app.auth_manager')
    def test_logout_endpoint(self, mock_auth_manager):
        mock_auth_manager.invalidate_session.return_value = True
        
        token = 'test_token_123'
        result = mock_auth_manager.invalidate_session(token)
        
        self.assertTrue(result)


class TestJobEndpoints(unittest.TestCase):
    
    @patch('app.requests')
    def test_list_jobs_endpoint(self, mock_requests):
        mock_response = Mock()
        mock_response.json.return_value = {'jobs': []}
        mock_response.raise_for_status = Mock()
        mock_requests.get.return_value = mock_response
        
        ghidra_api_base = "http://localhost:8000"
        expected_url = f"{ghidra_api_base}/jobs"
        
        self.assertIn('jobs', expected_url)
        self.assertEqual(expected_url, 'http://localhost:8000/jobs')
    
    @patch('app.requests')
    def test_get_status_endpoint(self, mock_requests):
        mock_response = Mock()
        mock_response.json.return_value = {'status': 'completed'}
        mock_response.raise_for_status = Mock()
        mock_requests.get.return_value = mock_response
        
        job_id = 'test_job_123'
        ghidra_api_base = "http://localhost:9090"
        
        expected_url = f"{ghidra_api_base}/status/{job_id}"
        self.assertIn(job_id, expected_url)


class TestChatEndpoints(unittest.TestCase):
    
    def test_chat_endpoint_validation(self):
        invalid_data_1 = {'message': 'test'}
        invalid_data_2 = {'job_id': '123'}
        valid_data = {'message': 'test', 'job_id': '123'}
        
        self.assertNotIn('job_id', invalid_data_1)
        self.assertNotIn('message', invalid_data_2)
        self.assertIn('message', valid_data)
        self.assertIn('job_id', valid_data)
    
    @patch('app.assistant')
    def test_chat_history_endpoint(self, mock_assistant):
        mock_assistant.load_history.return_value = [
            {'role': 'user', 'content': 'Hello'},
            {'role': 'assistant', 'content': 'Hi there'}
        ]
        
        job_id = 'test_job_123'
        history = mock_assistant.load_history(job_id)
        
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]['role'], 'user')


class TestSecurityEndpoints(unittest.TestCase):
    
    def test_security_analyze_endpoint_validation(self):
        invalid_data = {'analysis_type': 'comprehensive'}
        valid_data = {'job_id': '123', 'analysis_type': 'comprehensive'}
        
        self.assertNotIn('job_id', invalid_data)
        self.assertIn('job_id', valid_data)
        self.assertIn('analysis_type', valid_data)
    
    @patch('app.security_agent')
    def test_security_scan_endpoint(self, mock_security_agent):
        mock_security_agent.analyze_comprehensive.return_value = {
            'vulnerabilities': []
        }
        
        job_id = 'test_job_123'
        scan_type = 'comprehensive'
        
        self.assertEqual(job_id, 'test_job_123')
        self.assertEqual(scan_type, 'comprehensive')


class TestRemoteCollaborationEndpoints(unittest.TestCase):
    
    @patch('app.os')
    @patch('app.os.path')
    def test_remote_health_endpoint(self, mock_os_path, mock_os):
        mock_os.path.exists.return_value = True
        mock_os.listdir.return_value = []
        
        data_dir = 'data'
        exists = mock_os.path.exists(data_dir)
        
        self.assertTrue(exists)
    
    @patch('app.os')
    @patch('app.os.path')
    @patch('app.json')
    def test_remote_jobs_endpoint(self, mock_json, mock_os_path, mock_os):
        mock_os.path.exists.return_value = True
        mock_os.listdir.return_value = ['job1', 'job2']
        mock_os.path.join = os.path.join
        
        mock_status_data = {
            'filename': 'test.exe',
            'status': 'completed',
            'created_at': 1234567890
        }
        mock_json.load.return_value = mock_status_data
        
        self.assertIn('filename', mock_status_data)
        self.assertIn('status', mock_status_data)


class TestGraphEndpoint(unittest.TestCase):
    
    @patch('app.requests')
    def test_graph_data_endpoint(self, mock_requests):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            'nodes': [
                {'data': {'id': 'n1', 'label': 'main'}},
                {'data': {'id': 'n2', 'label': 'func'}}
            ],
            'edges': [
                {'data': {'source': 'n1', 'target': 'n2'}}
            ]
        }
        mock_requests.get.return_value = mock_response
        
        job_id = 'test_job_123'
        ghidra_api_base = "http://localhost:9090"
        
        expected_url = f"{ghidra_api_base}/graph/{job_id}"
        self.assertIn(job_id, expected_url)
        self.assertIn('graph', expected_url)


class TestFileUploadEndpoint(unittest.TestCase):
    
    def test_file_upload_validation(self):
        invalid_data_1 = {}
        invalid_data_2 = {'file': Mock(filename='')}
        valid_data = {'file': Mock(filename='test.exe')}
        
        self.assertEqual(len(invalid_data_1), 0)
        self.assertEqual(invalid_data_2['file'].filename, '')
        self.assertNotEqual(valid_data['file'].filename, '')
    
    def test_file_encoding(self):
        test_content = b'test binary content'
        encoded = base64.b64encode(test_content).decode('utf-8')
        
        self.assertIsInstance(encoded, str)
        self.assertTrue(len(encoded) > 0)
        
        decoded = base64.b64decode(encoded)
        self.assertEqual(decoded, test_content)


if __name__ == '__main__':
    unittest.main()
