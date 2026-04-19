import jwt
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app, redirect
from models import User, Session

class AuthManager:
    def __init__(self, secret_key=None):
        self.secret_key = secret_key
        self.algorithm = 'HS256'
        self.token_expiry = timedelta(hours=24)

    def set_secret_key(self, secret_key):
        """Set JWT secret key at application startup."""
        self.secret_key = secret_key

    def _token_hash(self, token):
        """Stable token hash for session lookup and revocation."""
        return hashlib.sha256(token.encode('utf-8')).hexdigest()
    
    def generate_token(self, user_id):
        """Generate JWT token for user"""
        if not self.secret_key:
            raise RuntimeError("JWT secret key is not configured")
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + self.token_expiry,
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def decode_token(self, token):
        """Decode and validate JWT token"""
        if not self.secret_key:
            return None
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def verify_token(self, token):
        payload = self.decode_token(token)
        if payload:
            session = Session.query.filter_by(
                token_hash=self._token_hash(token),
                is_active=True
            ).first()
            if session and session.expires_at > datetime.utcnow():
                return payload['user_id']
        return None
    
    def create_session(self, user_id, token):
        """Create session record in database"""
        session = Session(
            user_id=user_id,
            token_hash=self._token_hash(token),
            expires_at=datetime.utcnow() + self.token_expiry
        )
        from models import db
        db.session.add(session)
        db.session.commit()
        return session
    
    def invalidate_session(self, token):
        """Invalidate a session"""
        session = Session.query.filter_by(token_hash=self._token_hash(token)).first()
        if session:
            session.is_active = False
            from models import db
            db.session.commit()
            return True
        return False

auth_manager = AuthManager()

def token_required(f):
    """Decorator to protect routes with JWT authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401

        if not token:
        
            accept_header = request.headers.get('Accept', '')
            if 'text/html' in accept_header:
                return redirect('/login')
            return jsonify({'error': 'Token is missing'}), 401
        
        user_id = auth_manager.verify_token(token)
        if not user_id:
            return jsonify({'error': 'Token is invalid or expired'}), 401
        
        request.current_user_id = user_id
        
        return f(*args, **kwargs)
    
    return decorated

def admin_required(f):
    """Decorator to protect routes requiring admin role"""
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        user = User.query.get(request.current_user_id)
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    
    return decorated
