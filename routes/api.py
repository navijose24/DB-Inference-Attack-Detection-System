import json
import traceback
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, g, current_app

from auth_utils import login_required, role_required
from models import (
    get_dashboard_stats, log_query, get_query_logs,
    get_alerts, mark_alert_reviewed, create_alert,
    get_audit_logs, verify_audit_chain, create_audit_log,
)
from database import execute_query

api_bp = Blueprint('api', __name__, url_prefix='/api')


# ── JSON helper for datetime fields ──────────────────────────────────

def _serialize(obj):
    """Make query-result dicts JSON-safe."""
    if isinstance(obj, list):
        return [_serialize(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, timedelta):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.decode(errors='replace')
    return obj


# ── Dashboard ─────────────────────────────────────────────────────────

@api_bp.route('/dashboard/stats')
@login_required
def dashboard_stats():
    user_id = request.args.get('user_id', type=int)
    stats = get_dashboard_stats(user_id=user_id)
    return jsonify(_serialize(stats))


# ── Query Analysis ────────────────────────────────────────────────────

@api_bp.route('/query/analyze', methods=['POST'])
@login_required
def analyze_query():
    data = request.get_json(silent=True) or {}
    query_text = data.get('query', '').strip()
    if not query_text:
        return jsonify({'error': 'No query provided'}), 400

    if len(query_text) > current_app.config['MAX_QUERY_LENGTH']:
        return jsonify({'error': 'Query too long'}), 400

    try:
        from detection.analyzer import QueryAnalyzer
        from detection.ml_detector import MLDetector
        from detection.combined_scorer import CombinedScorer

        analyzer = QueryAnalyzer()
        analysis = analyzer.analyze(query_text, user_id=g.user.get('user_id'))

        ml = MLDetector()
        ml_score = ml.score(query_text, analysis.get('parsed'))

        rule_score = analysis.get('risk_score', 0)
        scorer = CombinedScorer()
        combined_score = scorer.compute_combined_score(rule_score, ml_score)
        classification = scorer.classify(
            combined_score,
            block_threshold=current_app.config['RISK_THRESHOLD_BLOCK'],
            flag_threshold=current_app.config['RISK_THRESHOLD_FLAG']
        ).lower()

        is_blocked = classification == 'blocked'
        attack_types = analysis.get('attack_types', [])
        details = analysis.get('details', {})
        details['ml_score'] = ml_score
        details['rule_score'] = rule_score

        # Log to DB
        log_id = log_query(g.user['user_id'], query_text, combined_score,
                           classification, is_blocked, attack_types, json.dumps(details))

        # Create alert if risky
        if classification in ('blocked', 'flagged'):
            severity = 'critical' if classification == 'blocked' else 'warning'
            create_alert(log_id, g.user['user_id'], severity,
                         ', '.join(attack_types) if attack_types else 'suspicious_query',
                         f"{'Blocked' if is_blocked else 'Flagged'} query detected",
                         details)

        # Audit log
        create_audit_log(g.user['user_id'], 'query_analyzed',
                         json.dumps({'query': query_text[:200], 'classification': classification}))

        return jsonify(_serialize({
            'risk_score': round(combined_score, 4),
            'classification': classification,
            'attack_types': attack_types,
            'is_blocked': is_blocked,
            'details': details,
            'ml_score': round(ml_score, 4),
        }))

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


# ── Query Logs ────────────────────────────────────────────────────────

@api_bp.route('/queries')
@login_required
def queries():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    user_id = request.args.get('user_id', type=int)
    offset = (page - 1) * per_page
    logs = get_query_logs(user_id=user_id, limit=per_page, offset=offset)
    return jsonify(_serialize({'queries': logs, 'page': page, 'per_page': per_page}))


# ── Alerts ────────────────────────────────────────────────────────────

@api_bp.route('/alerts')
@login_required
def alerts():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    severity = request.args.get('severity')
    offset = (page - 1) * per_page
    alert_list = get_alerts(limit=per_page, offset=offset, severity=severity)
    return jsonify(_serialize({'alerts': alert_list, 'page': page, 'per_page': per_page}))


@api_bp.route('/alerts/<int:alert_id>/review', methods=['PUT'])
@role_required('admin')
def review_alert(alert_id):
    mark_alert_reviewed(alert_id, g.user['user_id'])
    create_audit_log(g.user['user_id'], 'alert_reviewed', json.dumps({'alert_id': alert_id}))
    return jsonify({'success': True})


# ── Audit ─────────────────────────────────────────────────────────────

@api_bp.route('/audit/logs')
@role_required('admin')
def audit_logs():
    limit = request.args.get('limit', 50, type=int)
    logs = get_audit_logs(limit=limit)
    return jsonify(_serialize({'logs': logs}))


@api_bp.route('/audit/verify')
@role_required('admin')
def audit_verify():
    is_valid, broken_at = verify_audit_chain()
    return jsonify({'valid': is_valid, 'broken_at_id': broken_at})


# ── Simulator: Execute ────────────────────────────────────────────────

@api_bp.route('/query/execute', methods=['POST'])
@login_required
def execute_sim_query():
    data = request.get_json(silent=True) or {}
    query_text = data.get('query', '').strip()
    if not query_text:
        return jsonify({'error': 'No query provided'}), 400

    if len(query_text) > current_app.config['MAX_QUERY_LENGTH']:
        return jsonify({'error': 'Query too long'}), 400

    try:
        from detection.analyzer import QueryAnalyzer
        from detection.ml_detector import MLDetector
        from detection.combined_scorer import CombinedScorer

        analyzer = QueryAnalyzer()
        analysis = analyzer.analyze(query_text, user_id=g.user.get('user_id'))

        ml = MLDetector()
        ml_score = ml.score(query_text, analysis.get('parsed'))

        rule_score = analysis.get('risk_score', 0)
        scorer = CombinedScorer()
        combined_score = scorer.compute_combined_score(rule_score, ml_score)
        classification = scorer.classify(
            combined_score,
            block_threshold=current_app.config['RISK_THRESHOLD_BLOCK'],
            flag_threshold=current_app.config['RISK_THRESHOLD_FLAG']
        ).lower()

        is_blocked = classification == 'blocked'
        attack_types = analysis.get('attack_types', [])
        details = analysis.get('details', {})
        details['ml_score'] = ml_score
        details['rule_score'] = rule_score

        log_id = log_query(g.user['user_id'], query_text, combined_score,
                           classification, is_blocked, attack_types, json.dumps(details))

        if is_blocked:
            create_alert(log_id, g.user['user_id'], 'critical',
                         ', '.join(attack_types) if attack_types else 'blocked_query',
                         'Blocked query in simulator', details)
            create_audit_log(g.user['user_id'], 'query_blocked',
                             json.dumps({'query': query_text[:200]}))
            return jsonify(_serialize({
                'error': 'Query blocked due to high risk',
                'risk_score': round(combined_score, 4),
                'classification': classification,
                'attack_types': attack_types,
                'is_blocked': True,
                'details': details,
                'ml_score': round(ml_score, 4),
            })), 403

        # Execute against employees table
        results = execute_query(query_text)

        if classification == 'flagged':
            create_alert(log_id, g.user['user_id'], 'warning',
                         ', '.join(attack_types) if attack_types else 'flagged_query',
                         'Flagged query in simulator', details)

        create_audit_log(g.user['user_id'], 'query_executed',
                         json.dumps({'query': query_text[:200], 'classification': classification}))

        return jsonify(_serialize({
            'results': results,
            'risk_score': round(combined_score, 4),
            'classification': classification,
            'attack_types': attack_types,
            'is_blocked': False,
            'details': details,
            'ml_score': round(ml_score, 4),
            'row_count': len(results) if isinstance(results, list) else 0,
        }))

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Execution failed: {str(e)}'}), 500
