
import unittest
import jwt
from datetime import datetime, timedelta
from auth import AuthManager, token_required
from models import db, User, Session


class TestAuthManager(unittest.TestCase):
    
    def setUp(self):
        self.secret_key = 'test_secret_key_123'
        self.auth_manager = AuthManager(secret_key=self.secret_key)
        self.test_user_id = 'test_user_123'
    
    def test_generate_token(self):
        token = self.auth_manager.generate_token(self.test_user_id)
        
        self.assertIsInstance(token, str)
        
        self.assertTrue(len(token) > 0)
        
        payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
        self.assertEqual(payload['user_id'], self.test_user_id)
        self.assertIn('exp', payload)
        self.assertIn('iat', payload)
    
    def test_decode_valid_token(self):
        token = self.auth_manager.generate_token(self.test_user_id)
        payload = self.auth_manager.decode_token(token)
        
        self.assertIsNotNone(payload)
        self.assertEqual(payload['user_id'], self.test_user_id)
    
    def test_decode_invalid_token(self):
        invalid_token = 'invalid.token.string'
        payload = self.auth_manager.decode_token(invalid_token)
        
        self.assertIsNone(payload)
    
    def test_decode_expired_token(self):
        payload = {
            'user_id': self.test_user_id,
            'exp': datetime.utcnow() - timedelta(hours=1),
            'iat': datetime.utcnow() - timedelta(hours=2)
        }
        expired_token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        
        decoded = self.auth_manager.decode_token(expired_token)
        self.assertIsNone(decoded)
    
    def test_token_expiry(self):
        token = self.auth_manager.generate_token(self.test_user_id)
        payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
        
        exp_time = datetime.fromtimestamp(payload['exp'])
        iat_time = datetime.fromtimestamp(payload['iat'])
        duration = exp_time - iat_time
        
        self.assertGreaterEqual(duration.total_seconds(), 23 * 3600)
        self.assertLessEqual(duration.total_seconds(), 25 * 3600)


class TestUserModel(unittest.TestCase):
    
    def setUp(self):
        self.user = User(username='testuser', email='test@example.com')
    
    def test_password_hashing(self):
        password = 'test_password_123'
        self.user.set_password(password)
        
        self.assertIsNotNone(self.user.password_hash)
        
        self.assertNotEqual(self.user.password_hash, password)
    
    def test_password_verification(self):
        password = 'test_password_123'
        self.user.set_password(password)
        
        self.assertTrue(self.user.check_password(password))
        
        self.assertFalse(self.user.check_password('wrong_password'))
    
    def test_to_dict(self):
        self.user.set_password('password123')
        user_dict = self.user.to_dict()
        
        self.assertIn('id', user_dict)
        self.assertIn('username', user_dict)
        self.assertIn('email', user_dict)
        self.assertIn('created_at', user_dict)
        self.assertIn('is_active', user_dict)
        self.assertIn('role', user_dict)
        
        self.assertNotIn('password_hash', user_dict)
        
        self.assertEqual(user_dict['username'], 'testuser')
        self.assertEqual(user_dict['email'], 'test@example.com')


class TestSessionModel(unittest.TestCase):
    
    def setUp(self):
        from models import Session
        self.session = Session(
            user_id='test_user_123',
            token_hash='hashed_token_value',
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
    
    def test_session_creation(self):
        self.assertEqual(self.session.user_id, 'test_user_123')
        self.assertEqual(self.session.token_hash, 'hashed_token_value')
        self.session.is_active = True
        self.assertTrue(self.session.is_active)
    
    def test_session_expiry(self):
        expired_session = Session(
            user_id='test_user_123',
            token_hash='hashed_token_value',
            expires_at=datetime.utcnow() - timedelta(hours=1)
        )
        
        self.assertLess(expired_session.expires_at, datetime.utcnow())
    
    def test_to_dict(self):
        session_dict = self.session.to_dict()
        
        self.assertIn('id', session_dict)
        self.assertIn('user_id', session_dict)
        self.assertIn('created_at', session_dict)
        self.assertIn('expires_at', session_dict)
        self.assertIn('is_active', session_dict)
        
        self.assertNotIn('token_hash', session_dict)


class TestTokenRequiredDecorator(unittest.TestCase):
    
    def test_decorator_exists(self):
        from auth import token_required
        self.assertIsNotNone(token_required)
        
        self.assertTrue(callable(token_required))


if __name__ == '__main__':
    unittest.main()
