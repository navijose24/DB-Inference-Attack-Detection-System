import json
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, render_template

from config import Config
from database import init_db
from auth_utils import login_required, role_required  # noqa: F401 — re-export for convenience

app = Flask(__name__)
app.config.from_object(Config)


# ── Error Handlers ────────────────────────────────────────────────────

def _is_api():
    return request.path.startswith('/api/')


@app.errorhandler(401)
def unauthorized(e):
    if _is_api():
        return jsonify({'error': 'Authentication required'}), 401
    return render_template('login.html'), 401


@app.errorhandler(403)
def forbidden(e):
    if _is_api():
        return jsonify({'error': 'Forbidden'}), 403
    return render_template('403.html'), 403


@app.errorhandler(404)
def not_found(e):
    if _is_api():
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    if _is_api():
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500


# ── JSON serializer for datetimes ─────────────────────────────────────

class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, timedelta):
            return str(o)
        return super().default(o)


app.json_encoder = DateTimeEncoder


# ── Blueprint Registration ────────────────────────────────────────────

from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.api import api_bp

app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(api_bp)


# ── Init ──────────────────────────────────────────────────────────────

try:
    init_db(app)
except Exception:
    # DB may not be available during template development
    pass


if __name__ == '__main__':
    app.run(debug=True, port=5000)
