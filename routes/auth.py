from datetime import datetime, timedelta

import bcrypt
import jwt
from flask import Blueprint, request, session, jsonify, current_app, g

from models import create_user, get_user_by_username

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400

    user = get_user_by_username(username)
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    token = jwt.encode(
        {'user_id': user['id'], 'username': user['username'], 'role': user['role'],
         'exp': datetime.utcnow() + timedelta(seconds=current_app.config['PERMANENT_SESSION_LIFETIME'])},
        current_app.config['SECRET_KEY'], algorithm='HS256',
    )
    session['token'] = token
    return jsonify({
        'success': True,
        'token': token,
        'user': {'id': user['id'], 'username': user['username'], 'role': user['role']},
    })


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'analyst')

    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400

    if get_user_by_username(username):
        return jsonify({'success': False, 'error': 'Username already exists'}), 409

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_id = create_user(username, password_hash, role)
    return jsonify({'success': True, 'user': {'id': user_id, 'username': username, 'role': role}}), 201


@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'})


@auth_bp.route('/me', methods=['GET'])
def me():
    token = session.get('token')
    if not token:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({
            'user': {'id': payload['user_id'], 'username': payload['username'], 'role': payload['role']},
        })
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
