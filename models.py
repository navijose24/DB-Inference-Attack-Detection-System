import hashlib
import json
from datetime import datetime

from database import execute_query


# ── Users ──────────────────────────────────────────────────────────────

def create_user(username, password_hash, role='analyst'):
    return execute_query(
        "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
        (username, password_hash, role), fetch=False,
    )


def get_user_by_username(username):
    rows = execute_query("SELECT * FROM users WHERE username = %s", (username,))
    return rows[0] if rows else None


def get_user_by_id(user_id):
    rows = execute_query("SELECT * FROM users WHERE id = %s", (user_id,))
    return rows[0] if rows else None


# ── Query Logs ─────────────────────────────────────────────────────────

def log_query(user_id, query_text, risk_score, classification, is_blocked, attack_types, details):
    return execute_query(
        """INSERT INTO query_logs
           (user_id, query_text, risk_score, classification, is_blocked, attack_types, details)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (user_id, query_text, risk_score, classification, is_blocked,
         json.dumps(attack_types) if isinstance(attack_types, (list, dict)) else attack_types,
         json.dumps(details) if isinstance(details, dict) else details),
        fetch=False,
    )


def get_query_logs(user_id=None, limit=50, offset=0):
    if user_id:
        return execute_query(
            "SELECT * FROM query_logs WHERE user_id = %s ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (user_id, limit, offset),
        )
    return execute_query(
        "SELECT * FROM query_logs ORDER BY created_at DESC LIMIT %s OFFSET %s",
        (limit, offset),
    )


# ── Alerts ─────────────────────────────────────────────────────────────

def create_alert(query_log_id, user_id, severity, attack_type, description, details=None):
    return execute_query(
        """INSERT INTO security_alerts
           (query_log_id, user_id, severity, attack_type, description, details)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (query_log_id, user_id, severity, attack_type, description,
         json.dumps(details) if isinstance(details, dict) else details),
        fetch=False,
    )


def get_alerts(limit=50, offset=0, severity=None):
    if severity:
        return execute_query(
            "SELECT * FROM security_alerts WHERE severity = %s ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (severity, limit, offset),
        )
    return execute_query(
        "SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT %s OFFSET %s",
        (limit, offset),
    )


def mark_alert_reviewed(alert_id, reviewed_by):
    execute_query(
        "UPDATE security_alerts SET is_reviewed = TRUE, reviewed_by = %s, reviewed_at = NOW() WHERE id = %s",
        (reviewed_by, alert_id), fetch=False,
    )


# ── Audit Logs (SHA-256 hash chain) ───────────────────────────────────

def _compute_hash(prev_hash, action, details, timestamp):
    raw = f"{prev_hash}{action}{details}{timestamp}"
    return hashlib.sha256(raw.encode()).hexdigest()


def create_audit_log(user_id, action, details, prev_hash=None):
    if prev_hash is None:
        rows = execute_query("SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1")
        prev_hash = rows[0]['hash'] if rows else '0' * 64

    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    new_hash = _compute_hash(prev_hash, action, details, timestamp)
    return execute_query(
        """INSERT INTO audit_logs (user_id, action, details, prev_hash, hash, created_at)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (user_id, action, details, prev_hash, new_hash, timestamp),
        fetch=False,
    )


def get_audit_logs(limit=50):
    return execute_query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT %s", (limit,))


def verify_audit_chain():
    """Walk the entire chain and verify each hash. Returns (is_valid, broken_at_id_or_None)."""
    rows = execute_query("SELECT * FROM audit_logs ORDER BY id ASC")
    if not rows:
        return True, None

    for i, row in enumerate(rows):
        expected_prev = rows[i - 1]['hash'] if i > 0 else '0' * 64
        if row['prev_hash'] != expected_prev:
            return False, row['id']

        ts = row['created_at']
        if isinstance(ts, datetime):
            ts = ts.strftime('%Y-%m-%d %H:%M:%S')
        expected_hash = _compute_hash(row['prev_hash'], row['action'], row['details'], ts)
        if row['hash'] != expected_hash:
            return False, row['id']

    return True, None


# ── Dashboard Stats ───────────────────────────────────────────────────

def get_dashboard_stats(user_id=None):
    user_filter = " WHERE user_id = %s" if user_id else ""
    params = (user_id,) if user_id else ()

    total = execute_query(f"SELECT COUNT(*) AS c FROM query_logs{user_filter}", params)[0]['c']
    blocked = execute_query(f"SELECT COUNT(*) AS c FROM query_logs{user_filter} AND is_blocked = TRUE" if user_id
                            else "SELECT COUNT(*) AS c FROM query_logs WHERE is_blocked = TRUE",
                            params if user_id else ())[0]['c']
    flagged = execute_query(
        f"SELECT COUNT(*) AS c FROM query_logs{user_filter}{' AND' if user_id else ' WHERE'} classification = 'flagged'",
        params)[0]['c']
    safe = total - blocked - flagged

    total_alerts = execute_query("SELECT COUNT(*) AS c FROM security_alerts")[0]['c']

    severity_rows = execute_query(
        "SELECT severity, COUNT(*) AS c FROM security_alerts GROUP BY severity")
    alert_counts_by_severity = {r['severity']: r['c'] for r in severity_rows}

    hourly = execute_query(
        f"""SELECT HOUR(created_at) AS hour, COUNT(*) AS count
            FROM query_logs
            WHERE created_at >= NOW() - INTERVAL 24 HOUR {' AND user_id = %s' if user_id else ''}
            GROUP BY HOUR(created_at) ORDER BY hour""",
        params)

    attack_rows = execute_query(
        "SELECT attack_types, COUNT(*) AS c FROM query_logs WHERE attack_types IS NOT NULL AND attack_types != '[]' GROUP BY attack_types")
    attack_dist = {}
    for r in attack_rows:
        try:
            types = json.loads(r['attack_types']) if isinstance(r['attack_types'], str) else r['attack_types']
            for t in (types if isinstance(types, list) else [types]):
                attack_dist[t] = attack_dist.get(t, 0) + r['c']
        except (json.JSONDecodeError, TypeError):
            pass

    recent_alerts = execute_query("SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT 5")

    return {
        'total_queries': total,
        'blocked_queries': blocked,
        'flagged_queries': flagged,
        'safe_queries': safe,
        'total_alerts': total_alerts,
        'alert_counts_by_severity': alert_counts_by_severity,
        'queries_last_24h': hourly,
        'attack_type_distribution': attack_dist,
        'recent_alerts': recent_alerts,
    }
