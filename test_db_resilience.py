"""
Verification test for database lazy initialization and connection error handling.
"""
from app import app
from database import get_db

def test_db_error_handling():
    # 1. Calling get_db() within app context when MySQL is unreachable raises descriptive RuntimeError
    with app.app_context():
        try:
            get_db()
            assert False, "Expected RuntimeError when database is unreachable"
        except RuntimeError as e:
            assert "Ensure MySQL is running" in str(e), f"Unexpected message: {e}"

    # 2. POST /auth/login returns JSON 503 with error description
    client = app.test_client()
    res = client.post('/auth/login', json={'username': 'admin', 'password': 'admin123'})
    assert res.status_code == 503, f"Expected 503, got {res.status_code}"
    data = res.get_json()
    assert data and 'error' in data, "Expected JSON error in response"
    assert "Ensure MySQL is running" in data['error']
    print("✔ Database connection error handling and resilience verified.")

if __name__ == '__main__':
    test_db_error_handling()
