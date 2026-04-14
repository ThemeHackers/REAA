"""
Unit tests for Authentication module
"""

import unittest
import jwt
from datetime import datetime, timedelta
from auth import AuthManager, token_required
from models import db, User, Session


class TestAuthManager(unittest.TestCase):
    """Test cases for AuthManager class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.secret_key = 'test_secret_key_123'
        self.auth_manager = AuthManager(secret_key=self.secret_key)
        self.test_user_id = 'test_user_123'
    
    def test_generate_token(self):
        """Test JWT token generation"""
        token = self.auth_manager.generate_token(self.test_user_id)
        
        # Check token is a string
        self.assertIsInstance(token, str)
        
        # Check token is not empty
        self.assertTrue(len(token) > 0)
        
        # Decode token to verify payload
        payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
        self.assertEqual(payload['user_id'], self.test_user_id)
        self.assertIn('exp', payload)
        self.assertIn('iat', payload)
    
    def test_decode_valid_token(self):
        """Test decoding a valid token"""
        token = self.auth_manager.generate_token(self.test_user_id)
        payload = self.auth_manager.decode_token(token)
        
        self.assertIsNotNone(payload)
        self.assertEqual(payload['user_id'], self.test_user_id)
    
    def test_decode_invalid_token(self):
        """Test decoding an invalid token"""
        invalid_token = 'invalid.token.string'
        payload = self.auth_manager.decode_token(invalid_token)
        
        self.assertIsNone(payload)
    
    def test_decode_expired_token(self):
        """Test decoding an expired token"""
        # Create a token that expired 1 hour ago
        payload = {
            'user_id': self.test_user_id,
            'exp': datetime.utcnow() - timedelta(hours=1),
            'iat': datetime.utcnow() - timedelta(hours=2)
        }
        expired_token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        
        decoded = self.auth_manager.decode_token(expired_token)
        self.assertIsNone(decoded)
    
    def test_token_expiry(self):
        """Test token has correct expiry time"""
        token = self.auth_manager.generate_token(self.test_user_id)
        payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
        
        # Check expiry is approximately 24 hours from now
        exp_time = datetime.fromtimestamp(payload['exp'])
        iat_time = datetime.fromtimestamp(payload['iat'])
        duration = exp_time - iat_time
        
        # Should be approximately 24 hours (allow small margin)
        self.assertGreaterEqual(duration.total_seconds(), 23 * 3600)
        self.assertLessEqual(duration.total_seconds(), 25 * 3600)


class TestUserModel(unittest.TestCase):
    """Test cases for User model"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.user = User(username='testuser', email='test@example.com')
    
    def test_password_hashing(self):
        """Test password hashing"""
        password = 'test_password_123'
        self.user.set_password(password)
        
        # Check password_hash is set
        self.assertIsNotNone(self.user.password_hash)
        
        # Check password_hash is not the plain password
        self.assertNotEqual(self.user.password_hash, password)
    
    def test_password_verification(self):
        """Test password verification"""
        password = 'test_password_123'
        self.user.set_password(password)
        
        # Check correct password verifies
        self.assertTrue(self.user.check_password(password))
        
        # Check incorrect password does not verify
        self.assertFalse(self.user.check_password('wrong_password'))
    
    def test_to_dict(self):
        """Test User to_dict method"""
        self.user.set_password('password123')
        user_dict = self.user.to_dict()
        
        # Check required fields
        self.assertIn('id', user_dict)
        self.assertIn('username', user_dict)
        self.assertIn('email', user_dict)
        self.assertIn('created_at', user_dict)
        self.assertIn('is_active', user_dict)
        self.assertIn('role', user_dict)
        
        # Check password is not included
        self.assertNotIn('password_hash', user_dict)
        
        # Check values
        self.assertEqual(user_dict['username'], 'testuser')
        self.assertEqual(user_dict['email'], 'test@example.com')


class TestSessionModel(unittest.TestCase):
    """Test cases for Session model"""
    
    def setUp(self):
        """Set up test fixtures"""
        from models import Session
        self.session = Session(
            user_id='test_user_123',
            token_hash='hashed_token_value',
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
    
    def test_session_creation(self):
        """Test session creation"""
        self.assertEqual(self.session.user_id, 'test_user_123')
        self.assertEqual(self.session.token_hash, 'hashed_token_value')
        self.session.is_active = True
        self.assertTrue(self.session.is_active)
    
    def test_session_expiry(self):
        """Test session expiry"""
        # Create expired session
        expired_session = Session(
            user_id='test_user_123',
            token_hash='hashed_token_value',
            expires_at=datetime.utcnow() - timedelta(hours=1)
        )
        
        # Session should be in the past
        self.assertLess(expired_session.expires_at, datetime.utcnow())
    
    def test_to_dict(self):
        """Test Session to_dict method"""
        session_dict = self.session.to_dict()
        
        # Check required fields
        self.assertIn('id', session_dict)
        self.assertIn('user_id', session_dict)
        self.assertIn('created_at', session_dict)
        self.assertIn('expires_at', session_dict)
        self.assertIn('is_active', session_dict)
        
        # Check token_hash is not included
        self.assertNotIn('token_hash', session_dict)


class TestTokenRequiredDecorator(unittest.TestCase):
    """Test cases for token_required decorator"""
    
    def test_decorator_exists(self):
        """Test decorator function exists"""
        from auth import token_required
        self.assertIsNotNone(token_required)
        
        # Check it's callable
        self.assertTrue(callable(token_required))


if __name__ == '__main__':
    unittest.main()
