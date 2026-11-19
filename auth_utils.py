"""Auth decorators — extracted to avoid circular imports between app.py and routes."""
import functools

import jwt
from flask import request, session, jsonify, render_template, g, current_app


def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        token = session.get('token')
        if not token:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return render_template('login.html'), 401

        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            g.user = payload
        except jwt.ExpiredSignatureError:
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Token expired'}), 401
            return render_template('login.html'), 401
        except jwt.InvalidTokenError:
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Invalid token'}), 401
            return render_template('login.html'), 401

        return f(*args, **kwargs)
    return wrapper


def role_required(role):
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if g.user.get('role') != role:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Insufficient permissions'}), 403
                return render_template('403.html'), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator
