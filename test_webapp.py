"""
DB Sentinel — End-to-End Web App & REST API Verification
Tests Flask routes, session/JWT auth, detection pipeline, simulator execution,
and audit endpoints.
"""

import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app
from database import init_db

init_db(app)

client = app.test_client()

print("[*] Testing DB Sentinel Web Application Endpoints...")

# 1. Login page
res = client.get('/login')
assert res.status_code == 200, f"GET /login failed: {res.status_code}"
assert b"DB SENTINEL" in res.data
print("  ✔ /login renders correctly (200)")

# 2. Authenticate as admin
login_res = client.post('/auth/login', json={'username': 'admin', 'password': 'admin123'})
assert login_res.status_code == 200, f"Login failed: {login_res.status_code}"
login_data = login_res.get_json()
assert login_data['success'] is True
token = login_data['token']
print(f"  ✔ Admin authentication successful, JWT token issued.")

# Setup auth header
auth_headers = {'Authorization': f'Bearer {token}'}

# 3. Dashboard stats API
stats_res = client.get('/api/dashboard/stats', headers=auth_headers)
assert stats_res.status_code == 200, f"Dashboard stats failed: {stats_res.status_code}"
stats = stats_res.get_json()
assert 'total_queries' in stats
assert 'blocked_queries' in stats
print(f"  ✔ /api/dashboard/stats: {stats['total_queries']} queries, {stats['total_alerts']} alerts.")

# 4. Analyze safe query
analyze_safe = client.post('/api/query/analyze', headers=auth_headers, json={
    'query': 'SELECT department, COUNT(*) FROM employees GROUP BY department'
})
assert analyze_safe.status_code == 200
data_safe = analyze_safe.get_json()
assert data_safe['classification'] == 'safe'
print(f"  ✔ /api/query/analyze safe query: risk={data_safe['risk_score']} (safe)")

# 5. Analyze differencing attack query
# Send baseline first
client.post('/api/query/analyze', headers=auth_headers, json={
    'query': "SELECT AVG(salary) FROM employees WHERE department = 'IT'"
})
# Send targeted differencing
analyze_diff = client.post('/api/query/analyze', headers=auth_headers, json={
    'query': "SELECT AVG(salary) FROM employees WHERE department = 'IT' AND designation = 'Lead Security Architect'"
})
assert analyze_diff.status_code == 200
data_diff = analyze_diff.get_json()
print(f"  ✔ /api/query/analyze differencing: risk={data_diff['risk_score']} attacks={data_diff['attack_types']}")

# 6. Execute safe query in simulator against actual MySQL employees table
exec_safe = client.post('/api/query/execute', headers=auth_headers, json={
    'query': "SELECT department, COUNT(*) AS cnt FROM employees GROUP BY department"
})
assert exec_safe.status_code == 200
exec_data = exec_safe.get_json()
assert 'results' in exec_data
assert len(exec_data['results']) > 0
print(f"  ✔ /api/query/execute safe query: returned {len(exec_data['results'])} rows from MySQL.")

# 7. Execute attack query (should be blocked)
exec_blocked = client.post('/api/query/execute', headers=auth_headers, json={
    'query': "SELECT salary FROM employees WHERE employee_id = 1"
})
print(f"  ✔ /api/query/execute attack query status: {exec_blocked.status_code}")
blocked_data = exec_blocked.get_json()
assert exec_blocked.status_code == 403 or blocked_data.get('is_blocked') is True or blocked_data.get('classification') in ('blocked', 'flagged')
print(f"  ✔ Attack query intercepted and classified as: {blocked_data.get('classification')}")

# 8. Verify audit chain
audit_res = client.get('/api/audit/verify', headers=auth_headers)
assert audit_res.status_code == 200
audit_data = audit_res.get_json()
assert audit_data['valid'] is True
print(f"  ✔ /api/audit/verify: Audit chain cryptographic validity={audit_data['valid']}")

# 9. Query History
queries_res = client.get('/api/queries?page=1&per_page=10', headers=auth_headers)
assert queries_res.status_code == 200
print(f"  ✔ /api/queries: returned {len(queries_res.get_json()['queries'])} logs.")

# 10. Security Alerts
alerts_res = client.get('/api/alerts', headers=auth_headers)
assert alerts_res.status_code == 200
print(f"  ✔ /api/alerts: returned {len(alerts_res.get_json()['alerts'])} alerts.")

print("\n[✔✔✔] ALL END-TO-END WEB APP TESTS PASSED!")
