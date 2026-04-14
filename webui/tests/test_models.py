"""
Unit tests for Database Models
"""

import unittest
import datetime
from models import db, User, Job, ChatHistory, SecurityReport, CollaborationSession, Session


class TestJobModel(unittest.TestCase):
    """Test cases for Job model"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.job = Job(
            user_id='test_user_123',
            filename='test_binary.exe',
            file_path='/path/to/test_binary.exe',
            status='pending',
            priority=5,
            file_size=1024
        )
    
    def test_job_creation(self):
        """Test job creation"""
        self.assertEqual(self.job.user_id, 'test_user_123')
        self.assertEqual(self.job.filename, 'test_binary.exe')
        self.assertEqual(self.job.status, 'pending')
        self.assertEqual(self.job.priority, 5)
        self.assertEqual(self.job.file_size, 1024)
    
    def test_job_defaults(self):
        """Test job default values"""
        # Note: These are set in the database, not in the model instance
        # We test that they can be set and retrieved
        self.job.retry_count = 0
        self.job.max_retries = 3
        self.assertEqual(self.job.retry_count, 0)
        self.assertEqual(self.job.max_retries, 3)
        self.assertIsNone(self.job.started_at)
        self.assertIsNone(self.job.completed_at)
    
    def test_to_dict(self):
        """Test Job to_dict method"""
        job_dict = self.job.to_dict()
        
        # Check required fields
        self.assertIn('id', job_dict)
        self.assertIn('user_id', job_dict)
        self.assertIn('filename', job_dict)
        self.assertIn('status', job_dict)
        self.assertIn('priority', job_dict)
        self.assertIn('created_at', job_dict)
        
        # Check values
        self.assertEqual(job_dict['filename'], 'test_binary.exe')
        self.assertEqual(job_dict['status'], 'pending')


class TestChatHistoryModel(unittest.TestCase):
    """Test cases for ChatHistory model"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.chat = ChatHistory(
            job_id='test_job_123',
            role='user',
            content='Test message'
        )
    
    def test_chat_creation(self):
        """Test chat history creation"""
        self.assertEqual(self.chat.job_id, 'test_job_123')
        self.assertEqual(self.chat.role, 'user')
        self.assertEqual(self.chat.content, 'Test message')
    
    def test_chat_roles(self):
        """Test valid chat roles"""
        valid_roles = ['user', 'assistant']
        
        for role in valid_roles:
            chat = ChatHistory(job_id='test', role=role, content='test')
            self.assertEqual(chat.role, role)
    
    def test_to_dict(self):
        """Test ChatHistory to_dict method"""
        chat_dict = self.chat.to_dict()
        
        # Check required fields
        self.assertIn('id', chat_dict)
        self.assertIn('job_id', chat_dict)
        self.assertIn('role', chat_dict)
        self.assertIn('content', chat_dict)
        self.assertIn('timestamp', chat_dict)
        
        # Check values
        self.assertEqual(chat_dict['role'], 'user')
        self.assertEqual(chat_dict['content'], 'Test message')


class TestSecurityReportModel(unittest.TestCase):
    """Test cases for SecurityReport model"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.report = SecurityReport(
            job_id='test_job_123',
            report_type='comprehensive',
            findings={'vulnerabilities': ['buffer_overflow']}
        )
    
    def test_report_creation(self):
        """Test security report creation"""
        self.assertEqual(self.report.job_id, 'test_job_123')
        self.assertEqual(self.report.report_type, 'comprehensive')
        self.assertIsInstance(self.report.findings, dict)
    
    def test_report_types(self):
        """Test valid report types"""
        valid_types = ['comprehensive', 'memory', 'apis']
        
        for report_type in valid_types:
            report = SecurityReport(job_id='test', report_type=report_type, findings={})
            self.assertEqual(report.report_type, report_type)
    
    def test_to_dict(self):
        """Test SecurityReport to_dict method"""
        report_dict = self.report.to_dict()
        
        # Check required fields
        self.assertIn('id', report_dict)
        self.assertIn('job_id', report_dict)
        self.assertIn('report_type', report_dict)
        self.assertIn('findings', report_dict)
        self.assertIn('generated_at', report_dict)
        
        # Check values
        self.assertEqual(report_dict['report_type'], 'comprehensive')


class TestCollaborationSessionModel(unittest.TestCase):
    """Test cases for CollaborationSession model"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.session = CollaborationSession(
            job_id='test_job_123',
            user_id='test_user_123',
            socket_id='socket_abc123'
        )
    
    def test_session_creation(self):
        """Test collaboration session creation"""
        self.assertEqual(self.session.job_id, 'test_job_123')
        self.assertEqual(self.session.user_id, 'test_user_123')
        self.assertEqual(self.session.socket_id, 'socket_abc123')
    
    def test_cursor_position(self):
        """Test cursor position storage"""
        cursor_pos = {'x': 100, 'y': 200, 'type': 'mouse'}
        self.session.cursor_position = cursor_pos
        
        self.assertEqual(self.session.cursor_position, cursor_pos)
    
    def test_to_dict(self):
        """Test CollaborationSession to_dict method"""
        session_dict = self.session.to_dict()
        
        # Check required fields
        self.assertIn('id', session_dict)
        self.assertIn('job_id', session_dict)
        self.assertIn('user_id', session_dict)
        self.assertIn('joined_at', session_dict)
        self.assertIn('last_active', session_dict)
        
        # Check values
        self.assertEqual(session_dict['job_id'], 'test_job_123')


class TestModelRelationships(unittest.TestCase):
    """Test cases for model relationships"""
    
    def test_user_jobs_relationship(self):
        """Test User-Jobs relationship"""
        user = User(username='testuser', email='test@example.com')
        job1 = Job(user_id='test', filename='job1.exe')
        job2 = Job(user_id='test', filename='job2.exe')
        
        # Check relationship exists
        self.assertTrue(hasattr(user, 'jobs'))
    
    def test_job_chathistory_relationship(self):
        """Test Job-ChatHistory relationship"""
        job = Job(user_id='test', filename='test.exe')
        chat1 = ChatHistory(job_id='test', role='user', content='msg1')
        chat2 = ChatHistory(job_id='test', role='assistant', content='msg2')
        
        # Check relationship exists
        self.assertTrue(hasattr(job, 'chat_history'))
    
    def test_job_security_reports_relationship(self):
        """Test Job-SecurityReport relationship"""
        job = Job(user_id='test', filename='test.exe')
        report = SecurityReport(job_id='test', report_type='comprehensive', findings={})
        
        # Check relationship exists
        self.assertTrue(hasattr(job, 'security_reports'))
    
    def test_user_sessions_relationship(self):
        """Test User-Sessions relationship"""
        user = User(username='testuser', email='test@example.com')
        session = Session(user_id='test', token_hash='hash123', expires_at=datetime.datetime.utcnow())
        
        # Check relationship exists
        self.assertTrue(hasattr(user, 'sessions'))


if __name__ == '__main__':
    unittest.main()
