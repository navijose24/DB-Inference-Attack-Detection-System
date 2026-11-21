"""
Runnable verification test for simulator query analysis vs execution behavior.
Verifies that:
- Blocked queries return 403 with is_blocked=True and contain no executed results.
- Analysis queries return telemetry and never execute against the database.
- Safe execution returns real dynamic results matching the executed query.
"""
from app import app
from database import init_db

init_db(app)
client = app.test_client()

# Login as analyst/admin
login_res = client.post('/auth/login', json={'username': 'admin', 'password': 'admin123'})
assert login_res.status_code == 200, f"Login failed: {login_res.status_code}"
token = login_res.get_json()['token']
headers = {'Authorization': f'Bearer {token}'}

# 1. Analyze safe query - should return classification and NO 'results' key
res_analyze_safe = client.post('/api/query/analyze', headers=headers, json={
    'query': 'SELECT department, COUNT(*) FROM employees GROUP BY department'
})
assert res_analyze_safe.status_code == 200
data_analyze_safe = res_analyze_safe.get_json()
assert 'results' not in data_analyze_safe, "Analyze must not return execution results"
assert data_analyze_safe['is_blocked'] is False

# 2. Analyze blocked query - should return classification and NO 'results' key
res_analyze_blocked = client.post('/api/query/analyze', headers=headers, json={
    'query': 'SELECT salary FROM employees WHERE employee_id = 1'
})
assert res_analyze_blocked.status_code == 200
data_analyze_blocked = res_analyze_blocked.get_json()
assert 'results' not in data_analyze_blocked, "Analyze must not return execution results"
assert data_analyze_blocked['is_blocked'] is True
assert data_analyze_blocked['classification'] == 'blocked'

# 3. Execute blocked query - must return 403, is_blocked=True, and NO results
res_exec_blocked = client.post('/api/query/execute', headers=headers, json={
    'query': 'SELECT salary FROM employees WHERE employee_id = 1'
})
assert res_exec_blocked.status_code == 403
data_exec_blocked = res_exec_blocked.get_json()
assert data_exec_blocked.get('is_blocked') is True
assert 'results' not in data_exec_blocked, "Blocked query must not execute or return results"

# 4. Execute safe query A
res_exec_a = client.post('/api/query/execute', headers=headers, json={
    'query': 'SELECT department, COUNT(*) AS total_dept FROM employees GROUP BY department'
})
assert res_exec_a.status_code == 200
data_a = res_exec_a.get_json()
assert 'results' in data_a
assert len(data_a['results']) == 8
assert 'total_dept' in data_a['results'][0]

# 5. Execute safe query B - returns distinct results reflecting Query B
res_exec_b = client.post('/api/query/execute', headers=headers, json={
    'query': 'SELECT department, designation FROM employees LIMIT 2'
})
assert res_exec_b.status_code == 200
data_b = res_exec_b.get_json()
assert len(data_b['results']) == 2
assert 'designation' in data_b['results'][0]
assert 'total_dept' not in data_b['results'][0]

print("✔ All simulator execution and blocked query checks passed successfully.")
