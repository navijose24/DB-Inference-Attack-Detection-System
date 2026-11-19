from flask import Blueprint, render_template

from auth_utils import login_required, role_required

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/login')
def login_page():
    return render_template('login.html')


@dashboard_bp.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')


@dashboard_bp.route('/queries')
@login_required
def queries():
    return render_template('queries.html')


@dashboard_bp.route('/alerts')
@login_required
def alerts():
    return render_template('alerts.html')


@dashboard_bp.route('/audit')
@role_required('admin')
def audit():
    return render_template('audit.html')


@dashboard_bp.route('/simulator')
@login_required
def simulator():
    return render_template('simulator.html')
