"""
DB Sentinel — Comprehensive System Verification & Self-Test Suite
Assert-based verification of authentication, inference detection, ML scoring,
database integration, and audit chain integrity.
"""

import sys
import os
import json

# Ensure project root is on python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config import Config
from database import init_db, execute_query
from models import (
    get_user_by_username, get_dashboard_stats,
    log_query, create_alert, verify_audit_chain, create_audit_log
)
from detection.analyzer import QueryAnalyzer
from detection.ml_detector import MLDetector
from detection.combined_scorer import CombinedScorer
import bcrypt
import jwt


def test_database():
    print("[1/7] Testing MySQL connection & employee records...")
    rows = execute_query("SELECT COUNT(*) AS c FROM employees")
    count = rows[0]['c']
    assert count == 50, f"Expected 50 employee records, found {count}"
    print(f"      ✔ 50 employee records verified in MySQL.")


def test_auth():
    print("[2/7] Testing authentication & RBAC...")
    admin = get_user_by_username('admin')
    assert admin is not None, "Admin user not found"
    assert bcrypt.checkpw(b'admin123', admin['password_hash'].encode('utf-8')), "Admin password verification failed"
    assert admin['role'] == 'admin', "Admin role mismatch"

    analyst = get_user_by_username('analyst')
    assert analyst is not None, "Analyst user not found"
    assert bcrypt.checkpw(b'analyst123', analyst['password_hash'].encode('utf-8')), "Analyst password verification failed"
    print("      ✔ User credentials and bcrypt hashing verified.")


def test_analyzer():
    print("[3/7] Testing QueryAnalyzer inference detection heuristics...")
    analyzer = QueryAnalyzer()

    # Safe query test
    safe_q = "SELECT department, COUNT(*) FROM employees GROUP BY department"
    res_safe = analyzer.analyze(safe_q, user_id=1)
    assert res_safe['risk_score'] < 0.4, f"Safe query got excessive risk score: {res_safe['risk_score']}"
    print(f"      ✔ Safe Query risk score: {res_safe['risk_score']:.2f}")

    # Differencing attack test
    # First query establish baseline
    q1 = "SELECT AVG(salary) FROM employees WHERE department = 'IT'"
    analyzer.analyze(q1, user_id=1)
    # Second query narrows down by 1 condition
    q2 = "SELECT AVG(salary) FROM employees WHERE department = 'IT' AND designation = 'Lead Security Architect'"
    res_diff = analyzer.analyze(q2, user_id=1)
    diff_score = res_diff['details']['differencing']['score']
    assert diff_score > 0.3, f"Differencing attack not detected properly (score: {diff_score})"
    print(f"      ✔ Differencing Attack heuristic score: {diff_score:.2f}")

    # Small set attack test
    q_small = "SELECT salary FROM employees WHERE employee_id = 101"
    res_small = analyzer.analyze(q_small, user_id=1)
    small_score = res_small['details']['small_set']['score']
    assert small_score > 0.5, f"Small-set attack not detected properly (score: {small_score})"
    print(f"      ✔ Small-Set Attack heuristic score: {small_score:.2f}")

    # Attribute inference test
    q_attr = "SELECT salary, ssn_last4 FROM employees WHERE department = 'IT' AND gender = 'M' AND city = 'New York'"
    res_attr = analyzer.analyze(q_attr, user_id=1)
    attr_score = res_attr['details']['attribute']['score']
    assert attr_score > 0.3, f"Attribute inference not detected properly (score: {attr_score})"
    print(f"      ✔ Attribute Inference heuristic score: {attr_score:.2f}")


def test_ml_detector():
    print("[4/7] Testing Isolation Forest ML anomaly scoring...")
    ml = MLDetector()
    score_normal = ml.score("SELECT department, COUNT(*) FROM employees GROUP BY department")
    score_attack = ml.score("SELECT salary FROM employees WHERE employee_id = 2 AND designation = 'Lead'")
    print(f"      Normal query ML anomaly score: {score_normal:.3f}")
    print(f"      Targeted query ML anomaly score: {score_attack:.3f}")
    assert 0.0 <= score_normal <= 1.0, "Anomaly score out of range [0, 1]"
    assert 0.0 <= score_attack <= 1.0, "Anomaly score out of range [0, 1]"
    print("      ✔ ML Isolation Forest model functioning correctly.")


def test_combined_scorer():
    print("[5/7] Testing Combined Scorer...")
    scorer = CombinedScorer(rule_weight=0.6, ml_weight=0.4)
    low = scorer.compute_combined_score(0.1, 0.1)
    high = scorer.compute_combined_score(0.9, 0.85)
    assert low < 0.3, f"Low threat score too high: {low}"
    assert high >= 0.8, f"High threat score too low: {high}"
    assert scorer.classify(high) == "BLOCKED"
    assert scorer.classify(low) == "SAFE"
    print(f"      ✔ Combined scoring logic confirmed: Low={low:.2f} ({scorer.classify(low)}), High={high:.2f} ({scorer.classify(high)})")


def test_audit_chain():
    print("[6/7] Testing SHA-256 tamper-evident audit ledger...")
    valid, broken_id = verify_audit_chain()
    assert valid is True, f"Audit chain broken at ID {broken_id}"

    # Append test log
    create_audit_log(1, 'UNIT_TEST_ACTION', 'Testing blockchain link append')
    valid2, broken_id2 = verify_audit_chain()
    assert valid2 is True, f"Audit chain broke after append at ID {broken_id2}"
    print("      ✔ SHA-256 cryptographic hash chain verified and tamper-evident.")


def test_dashboard_stats():
    print("[7/7] Testing Dashboard Analytics Aggregation...")
    stats = get_dashboard_stats()
    assert 'total_queries' in stats
    assert 'blocked_queries' in stats
    assert 'flagged_queries' in stats
    assert 'total_alerts' in stats
    print(f"      ✔ Telemetry Aggregated: {stats['total_queries']} queries, {stats['total_alerts']} alerts.")


if __name__ == '__main__':
    print("=" * 60)
    print("   DB SENTINEL — COMPREHENSIVE VERIFICATION SUITE")
    print("=" * 60)
    # Mock Flask app context for DB initialization
    class DummyApp:
        config = {
            'MYSQL_HOST': Config.MYSQL_HOST,
            'MYSQL_USER': Config.MYSQL_USER,
            'MYSQL_PASSWORD': Config.MYSQL_PASSWORD,
            'MYSQL_DB': Config.MYSQL_DB,
            'MYSQL_PORT': Config.MYSQL_PORT,
        }
    init_db(DummyApp())

    test_database()
    test_auth()
    test_analyzer()
    test_ml_detector()
    test_combined_scorer()
    test_audit_chain()
    test_dashboard_stats()
    print("=" * 60)
    print("   [✔✔✔] ALL 7 VERIFICATION PHASES PASSED SUCCESSFULLY!")
    print("=" * 60)
