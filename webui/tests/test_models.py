
import unittest
import datetime
from models import db, User, Job, ChatHistory, SecurityReport, CollaborationSession, Session


class TestJobModel(unittest.TestCase):
    
    def setUp(self):
        self.job = Job(
            user_id='test_user_123',
            filename='test_binary.exe',
            file_path='/path/to/test_binary.exe',
            status='pending',
            priority=5,
            file_size=1024
        )
    
    def test_job_creation(self):
        self.assertEqual(self.job.user_id, 'test_user_123')
        self.assertEqual(self.job.filename, 'test_binary.exe')
        self.assertEqual(self.job.status, 'pending')
        self.assertEqual(self.job.priority, 5)
        self.assertEqual(self.job.file_size, 1024)
    
    def test_job_defaults(self):
        self.job.retry_count = 0
        self.job.max_retries = 3
        self.assertEqual(self.job.retry_count, 0)
        self.assertEqual(self.job.max_retries, 3)
        self.assertIsNone(self.job.started_at)
        self.assertIsNone(self.job.completed_at)
    
    def test_to_dict(self):
        job_dict = self.job.to_dict()
        
        self.assertIn('id', job_dict)
        self.assertIn('user_id', job_dict)
        self.assertIn('filename', job_dict)
        self.assertIn('status', job_dict)
        self.assertIn('priority', job_dict)
        self.assertIn('created_at', job_dict)
        
        self.assertEqual(job_dict['filename'], 'test_binary.exe')
        self.assertEqual(job_dict['status'], 'pending')


class TestChatHistoryModel(unittest.TestCase):
    
    def setUp(self):
        self.chat = ChatHistory(
            job_id='test_job_123',
            role='user',
            content='Test message'
        )
    
    def test_chat_creation(self):
        self.assertEqual(self.chat.job_id, 'test_job_123')
        self.assertEqual(self.chat.role, 'user')
        self.assertEqual(self.chat.content, 'Test message')
    
    def test_chat_roles(self):
        valid_roles = ['user', 'assistant']
        
        for role in valid_roles:
            chat = ChatHistory(job_id='test', role=role, content='test')
            self.assertEqual(chat.role, role)
    
    def test_to_dict(self):
        chat_dict = self.chat.to_dict()
        
        self.assertIn('id', chat_dict)
        self.assertIn('job_id', chat_dict)
        self.assertIn('role', chat_dict)
        self.assertIn('content', chat_dict)
        self.assertIn('timestamp', chat_dict)
        
        self.assertEqual(chat_dict['role'], 'user')
        self.assertEqual(chat_dict['content'], 'Test message')


class TestSecurityReportModel(unittest.TestCase):
    
    def setUp(self):
        self.report = SecurityReport(
            job_id='test_job_123',
            report_type='comprehensive',
            findings={'vulnerabilities': ['buffer_overflow']}
        )
    
    def test_report_creation(self):
        self.assertEqual(self.report.job_id, 'test_job_123')
        self.assertEqual(self.report.report_type, 'comprehensive')
        self.assertIsInstance(self.report.findings, dict)
    
    def test_report_types(self):
        valid_types = ['comprehensive', 'memory', 'apis']
        
        for report_type in valid_types:
            report = SecurityReport(job_id='test', report_type=report_type, findings={})
            self.assertEqual(report.report_type, report_type)
    
    def test_to_dict(self):
        report_dict = self.report.to_dict()
        
        self.assertIn('id', report_dict)
        self.assertIn('job_id', report_dict)
        self.assertIn('report_type', report_dict)
        self.assertIn('findings', report_dict)
        self.assertIn('generated_at', report_dict)
        
        self.assertEqual(report_dict['report_type'], 'comprehensive')


class TestCollaborationSessionModel(unittest.TestCase):
    
    def setUp(self):
        self.session = CollaborationSession(
            job_id='test_job_123',
            user_id='test_user_123',
            socket_id='socket_abc123'
        )
    
    def test_session_creation(self):
        self.assertEqual(self.session.job_id, 'test_job_123')
        self.assertEqual(self.session.user_id, 'test_user_123')
        self.assertEqual(self.session.socket_id, 'socket_abc123')
    
    def test_cursor_position(self):
        cursor_pos = {'x': 100, 'y': 200, 'type': 'mouse'}
        self.session.cursor_position = cursor_pos
        
        self.assertEqual(self.session.cursor_position, cursor_pos)
    
    def test_to_dict(self):
        session_dict = self.session.to_dict()
        
        self.assertIn('id', session_dict)
        self.assertIn('job_id', session_dict)
        self.assertIn('user_id', session_dict)
        self.assertIn('joined_at', session_dict)
        self.assertIn('last_active', session_dict)
        
        self.assertEqual(session_dict['job_id'], 'test_job_123')


class TestModelRelationships(unittest.TestCase):
    
    def test_user_jobs_relationship(self):
        user = User(username='testuser', email='test@example.com')
        job1 = Job(user_id='test', filename='job1.exe')
        job2 = Job(user_id='test', filename='job2.exe')
        
        self.assertTrue(hasattr(user, 'jobs'))
    
    def test_job_chathistory_relationship(self):
        job = Job(user_id='test', filename='test.exe')
        chat1 = ChatHistory(job_id='test', role='user', content='msg1')
        chat2 = ChatHistory(job_id='test', role='assistant', content='msg2')
        
        self.assertTrue(hasattr(job, 'chat_history'))
    
    def test_job_security_reports_relationship(self):
        job = Job(user_id='test', filename='test.exe')
        report = SecurityReport(job_id='test', report_type='comprehensive', findings={})
        
        self.assertTrue(hasattr(job, 'security_reports'))
    
    def test_user_sessions_relationship(self):
        user = User(username='testuser', email='test@example.com')
        session = Session(user_id='test', token_hash='hash123', expires_at=datetime.datetime.utcnow())
        
        self.assertTrue(hasattr(user, 'sessions'))


if __name__ == '__main__':
    unittest.main()
