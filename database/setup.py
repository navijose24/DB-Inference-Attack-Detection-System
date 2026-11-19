"""
DB Sentinel — Database Setup and Seeder Script
Initializes the database, creates all tables, seeds synthetic confidential records,
and populates default administrative accounts and sample audit/alert logs.

Usage:
    python database/setup.py [--reset]
"""

import os
import sys
import argparse
import hashlib
from datetime import datetime, timedelta
import json
import bcrypt

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import Config

try:
    import mysql.connector
except ImportError:
    print("mysql-connector not found. Make sure dependencies are installed.")
    sys.exit(1)


def get_server_connection():
    """Connect to MySQL server without selecting a database."""
    return mysql.connector.connect(
        host=Config.MYSQL_HOST,
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        port=Config.MYSQL_PORT,
        autocommit=True
    )


def get_db_connection():
    """Connect directly to the db_sentinel database."""
    return mysql.connector.connect(
        host=Config.MYSQL_HOST,
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB,
        port=Config.MYSQL_PORT,
        autocommit=True
    )


def run_schema(reset=False):
    print("[*] Connecting to MySQL server...")
    conn = get_server_connection()
    cursor = conn.cursor()

    if reset:
        print("[!] Dropping existing database if present...")
        cursor.execute(f"DROP DATABASE IF EXISTS {Config.MYSQL_DB}")

    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {Config.MYSQL_DB}")
    cursor.close()
    conn.close()

    print("[*] Applying schema...")
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, 'r', encoding='utf-8') as f:
        schema_sql = f.read()

    db_conn = get_db_connection()
    cursor = db_conn.cursor()

    # Split statements
    statements = schema_sql.split(';')
    for stmt in statements:
        stmt = stmt.strip()
        if stmt:
            cursor.execute(stmt)

    cursor.close()
    db_conn.close()
    print("[+] Schema applied successfully.")


def seed_users():
    print("[*] Seeding default users...")
    db_conn = get_db_connection()
    cursor = db_conn.cursor(dictionary=True)

    users_data = [
        ('admin', 'admin123', 'admin'),
        ('analyst', 'analyst123', 'analyst'),
        ('viewer', 'viewer123', 'viewer')
    ]

    for username, raw_password, role in users_data:
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if not cursor.fetchone():
            hashed = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                (username, hashed, role)
            )
            print(f"    Created user '{username}' (role: {role})")

    cursor.close()
    db_conn.close()


def seed_employees():
    print("[*] Seeding 50 synthetic employee records...")
    db_conn = get_db_connection()
    cursor = db_conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM employees")
    count = cursor.fetchone()[0]
    if count >= 50:
        print(f"    Employees table already contains {count} records. Skipping.")
        cursor.close()
        db_conn.close()
        return

    cursor.execute("DELETE FROM employees")

    employees = [
        ('James', 'Smith', 'james.smith@sentinel-corp.com', '555-0101', 'IT', 'Chief Information Officer', 175000.00, 'M', '1980-04-12', '2015-03-01', '101 Pine St', 'New York', 'NY', '4912', 4.8),
        ('Sarah', 'Johnson', 'sarah.johnson@sentinel-corp.com', '555-0102', 'IT', 'Lead Security Architect', 145000.00, 'F', '1985-08-23', '2017-06-15', '204 Oak Ave', 'New York', 'NY', '8310', 4.9),
        ('Michael', 'Williams', 'michael.williams@sentinel-corp.com', '555-0103', 'IT', 'Senior Database Administrator', 125000.00, 'M', '1988-11-05', '2018-09-01', '305 Elm Rd', 'Jersey City', 'NJ', '1924', 4.2),
        ('Emily', 'Brown', 'emily.brown@sentinel-corp.com', '555-0104', 'IT', 'Senior DevOps Engineer', 120000.00, 'F', '1990-02-19', '2019-01-10', '412 Maple Dr', 'New York', 'NY', '7721', 4.5),
        ('David', 'Jones', 'david.jones@sentinel-corp.com', '555-0105', 'IT', 'Cybersecurity Analyst', 95000.00, 'M', '1993-07-30', '2020-04-01', '523 Cedar Ln', 'Brooklyn', 'NY', '3419', 4.0),
        ('Jessica', 'Garcia', 'jessica.garcia@sentinel-corp.com', '555-0106', 'IT', 'Junior Security Analyst', 68000.00, 'F', '1996-12-14', '2022-08-15', '634 Birch Way', 'Queens', 'NY', '6105', 3.8),
        ('Robert', 'Miller', 'robert.miller@sentinel-corp.com', '555-0107', 'IT', 'IT Support Specialist', 52000.00, 'M', '1998-05-22', '2023-02-01', '745 Spruce St', 'Bronx', 'NY', '9042', 3.5),
        
        ('Amanda', 'Davis', 'amanda.davis@sentinel-corp.com', '555-0108', 'Finance', 'Chief Financial Officer', 185000.00, 'F', '1979-09-18', '2014-11-01', '856 Walnut St', 'Greenwich', 'CT', '2241', 4.9),
        ('Daniel', 'Rodriguez', 'daniel.rodriguez@sentinel-corp.com', '555-0109', 'Finance', 'Finance Director', 150000.00, 'M', '1983-03-27', '2016-05-12', '967 Chestnut Ct', 'Stamford', 'CT', '5538', 4.6),
        ('Ashley', 'Martinez', 'ashley.martinez@sentinel-corp.com', '555-0110', 'Finance', 'Senior Financial Analyst', 105000.00, 'F', '1989-06-11', '2018-10-01', '178 Ash Blvd', 'White Plains', 'NY', '8814', 4.3),
        ('Christopher', 'Hernandez', 'christopher.hernandez@sentinel-corp.com', '555-0111', 'Finance', 'Senior Accountant', 92000.00, 'M', '1991-10-08', '2019-07-15', '289 Beech Rd', 'Yonkers', 'NY', '4402', 4.1),
        ('Melissa', 'Lopez', 'melissa.lopez@sentinel-corp.com', '555-0112', 'Finance', 'Payroll Specialist', 62000.00, 'F', '1994-01-25', '2021-03-20', '390 Willow Way', 'New Rochelle', 'NY', '1729', 3.9),
        ('Brian', 'Gonzalez', 'brian.gonzalez@sentinel-corp.com', '555-0113', 'Finance', 'Junior Auditor', 58000.00, 'M', '1997-04-17', '2023-01-09', '401 Poplar Ave', 'Hoboken', 'NJ', '6633', 3.7),

        ('Jennifer', 'Wilson', 'jennifer.wilson@sentinel-corp.com', '555-0114', 'HR', 'VP Human Resources', 160000.00, 'F', '1981-01-14', '2015-08-01', '512 Sycamore Pl', 'Summit', 'NJ', '3190', 4.7),
        ('Kevin', 'Anderson', 'kevin.anderson@sentinel-corp.com', '555-0115', 'HR', 'HR Operations Manager', 110000.00, 'M', '1986-07-29', '2017-12-01', '623 Alder Ln', 'Morristown', 'NJ', '7284', 4.4),
        ('Stephanie', 'Thomas', 'stephanie.thomas@sentinel-corp.com', '555-0116', 'HR', 'Talent Acquisition Lead', 88000.00, 'F', '1992-03-03', '2020-02-15', '734 Hickory Dr', 'New York', 'NY', '9912', 4.2),
        ('Jason', 'Taylor', 'jason.taylor@sentinel-corp.com', '555-0117', 'HR', 'Compensation Specialist', 78000.00, 'M', '1993-09-21', '2021-06-01', '845 Cypress St', 'Brooklyn', 'NY', '5031', 3.8),
        ('Nicole', 'Moore', 'nicole.moore@sentinel-corp.com', '555-0118', 'HR', 'HR Coordinator', 48000.00, 'F', '1999-08-16', '2023-05-15', '956 Magnolia Cir', 'Queens', 'NY', '2418', 3.6),

        ('Matthew', 'Jackson', 'matthew.jackson@sentinel-corp.com', '555-0119', 'Engineering', 'VP of Engineering', 195000.00, 'M', '1978-05-09', '2013-09-01', '167 Redwood Ter', 'Princeton', 'NJ', '8820', 4.9),
        ('Lauren', 'Martin', 'lauren.martin@sentinel-corp.com', '555-0120', 'Engineering', 'Principal Software Engineer', 165000.00, 'F', '1984-10-31', '2016-01-18', '278 Sequoia Blvd', 'New York', 'NY', '1145', 4.8),
        ('Ryan', 'Lee', 'ryan.lee@sentinel-corp.com', '555-0121', 'Engineering', 'Senior Full Stack Engineer', 135000.00, 'M', '1987-12-02', '2017-04-10', '389 Larchmont Ave', 'Jersey City', 'NJ', '4491', 4.5),
        ('Rachel', 'Perez', 'rachel.perez@sentinel-corp.com', '555-0122', 'Engineering', 'Senior Backend Engineer', 130000.00, 'F', '1990-04-15', '2018-08-20', '490 Highland Ave', 'Manhattan', 'NY', '6327', 4.4),
        ('Justin', 'White', 'justin.white@sentinel-corp.com', '555-0123', 'Engineering', 'Frontend Engineer', 102000.00, 'M', '1993-08-08', '2020-11-01', '501 Valley Rd', 'Hoboken', 'NJ', '9103', 4.1),
        ('Megan', 'Harris', 'megan.harris@sentinel-corp.com', '555-0124', 'Engineering', 'QA Automation Engineer', 90000.00, 'F', '1994-11-19', '2021-04-15', '612 Hillcrest Rd', 'Astoria', 'NY', '3782', 3.9),
        ('Brandon', 'Clark', 'brandon.clark@sentinel-corp.com', '555-0125', 'Engineering', 'Junior Software Engineer', 75000.00, 'M', '1998-03-25', '2022-09-01', '723 Sunset Blvd', 'Brooklyn', 'NY', '7540', 3.7),
        ('Hannah', 'Lewis', 'hannah.lewis@sentinel-corp.com', '555-0126', 'Engineering', 'Software Engineering Intern', 42000.00, 'F', '2001-06-30', '2023-06-01', '834 Park Pl', 'New York', 'NY', '1899', 4.0),

        ('Tyler', 'Robinson', 'tyler.robinson@sentinel-corp.com', '555-0127', 'Marketing', 'Chief Marketing Officer', 170000.00, 'M', '1982-02-18', '2016-03-01', '945 Forest Ave', 'Westport', 'CT', '5219', 4.7),
        ('Samantha', 'Walker', 'samantha.walker@sentinel-corp.com', '555-0128', 'Marketing', 'Digital Marketing Director', 128000.00, 'F', '1987-07-04', '2018-05-15', '156 Meadow Ln', 'New York', 'NY', '8043', 4.4),
        ('Andrew', 'Hall', 'andrew.hall@sentinel-corp.com', '555-0129', 'Marketing', 'Product Marketing Manager', 112000.00, 'M', '1989-09-12', '2019-09-01', '267 Brookside Dr', 'Stamford', 'CT', '2938', 4.2),
        ('Brittany', 'Allen', 'brittany.allen@sentinel-corp.com', '555-0130', 'Marketing', 'Content Strategist', 76000.00, 'F', '1993-01-29', '2021-01-15', '378 River Rd', 'Brooklyn', 'NY', '6712', 4.0),
        ('Joshua', 'Young', 'joshua.young@sentinel-corp.com', '555-0131', 'Marketing', 'SEO Specialist', 64000.00, 'M', '1996-05-14', '2022-04-01', '489 Lakeview Ter', 'Queens', 'NY', '9405', 3.8),

        ('Heather', 'King', 'heather.king@sentinel-corp.com', '555-0132', 'Sales', 'VP of Global Sales', 180000.00, 'F', '1980-08-08', '2015-02-01', '590 Ridge Rd', 'Darien', 'CT', '3821', 4.8),
        ('Nathan', 'Wright', 'nathan.wright@sentinel-corp.com', '555-0133', 'Sales', 'Enterprise Account Executive', 140000.00, 'M', '1986-11-20', '2017-07-10', '601 Overlook Ct', 'New York', 'NY', '7190', 4.6),
        ('Amber', 'Scott', 'amber.scott@sentinel-corp.com', '555-0134', 'Sales', 'Senior Account Executive', 118000.00, 'F', '1990-03-15', '2019-03-01', '712 Summit Ave', 'Hoboken', 'NJ', '1459', 4.3),
        ('Christian', 'Green', 'christian.green@sentinel-corp.com', '555-0135', 'Sales', 'Sales Development Manager', 95000.00, 'M', '1992-06-28', '2020-08-15', '823 Hillside Way', 'Jersey City', 'NJ', '5723', 4.1),
        ('Courtney', 'Baker', 'courtney.baker@sentinel-corp.com', '555-0136', 'Sales', 'Sales Development Rep', 55000.00, 'F', '1997-10-10', '2022-11-01', '934 Crestview Dr', 'Bronx', 'NY', '8034', 3.7),

        ('Jonathan', 'Adams', 'jonathan.adams@sentinel-corp.com', '555-0137', 'Operations', 'Chief Operating Officer', 190000.00, 'M', '1977-12-05', '2014-04-01', '145 Woodland Rd', 'Rye', 'NY', '4310', 4.9),
        ('Danielle', 'Nelson', 'danielle.nelson@sentinel-corp.com', '555-0138', 'Operations', 'Operations Director', 138000.00, 'F', '1985-04-19', '2017-10-01', '256 Beacon St', 'White Plains', 'NY', '7689', 4.5),
        ('Aaron', 'Carter', 'aaron.carter@sentinel-corp.com', '555-0139', 'Operations', 'Supply Chain Analyst', 82000.00, 'M', '1991-08-24', '2020-01-20', '367 Fairview Ave', 'Yonkers', 'NY', '1092', 4.0),
        ('Tiffany', 'Mitchell', 'tiffany.mitchell@sentinel-corp.com', '555-0140', 'Operations', 'Logistics Coordinator', 59000.00, 'F', '1995-02-11', '2022-05-15', '478 Spring St', 'Queens', 'NY', '5387', 3.8),

        ('Jeffrey', 'Perez', 'jeffrey.perez@sentinel-corp.com', '555-0141', 'Legal', 'General Counsel', 195000.00, 'M', '1976-03-30', '2013-06-01', '589 Broadway', 'New York', 'NY', '9271', 4.9),
        ('Kelly', 'Roberts', 'kelly.roberts@sentinel-corp.com', '555-0142', 'Legal', 'Senior Corporate Counsel', 152000.00, 'F', '1984-09-05', '2017-03-15', '690 Lexington Ave', 'New York', 'NY', '2548', 4.7),
        ('Sean', 'Turner', 'sean.turner@sentinel-corp.com', '555-0143', 'Legal', 'Compliance Director', 132000.00, 'M', '1988-01-22', '2019-11-01', '701 Madison Ave', 'New York', 'NY', '6832', 4.4),
        ('Diana', 'Phillips', 'diana.phillips@sentinel-corp.com', '555-0144', 'Legal', 'Paralegal Specialist', 65000.00, 'F', '1994-06-17', '2021-08-01', '812 Park Ave', 'New York', 'NY', '0194', 4.0),

        ('Gregory', 'Campbell', 'gregory.campbell@sentinel-corp.com', '555-0145', 'IT', 'Cloud Infrastructure Architect', 142000.00, 'M', '1986-05-18', '2018-02-01', '923 Hudson St', 'Hoboken', 'NJ', '3456', 4.6),
        ('Rebecca', 'Parker', 'rebecca.parker@sentinel-corp.com', '555-0146', 'Engineering', 'Data Platform Engineer', 128000.00, 'F', '1991-07-14', '2019-10-15', '134 Washington St', 'Jersey City', 'NJ', '7890', 4.3),
        ('Travis', 'Evans', 'travis.evans@sentinel-corp.com', '555-0147', 'Finance', 'Internal Auditor', 78000.00, 'M', '1993-12-08', '2021-07-01', '245 Grand St', 'New York', 'NY', '2345', 3.9),
        ('Victoria', 'Edwards', 'victoria.edwards@sentinel-corp.com', '555-0148', 'Marketing', 'Brand Experience Specialist', 70000.00, 'F', '1995-10-23', '2022-03-15', '356 Canal St', 'New York', 'NY', '6789', 3.8),
        ('Eric', 'Collins', 'eric.collins@sentinel-corp.com', '555-0149', 'Operations', 'Procurement Specialist', 66000.00, 'M', '1994-04-04', '2021-12-01', '467 Bowery', 'New York', 'NY', '1234', 3.7),
        ('Katherine', 'Stewart', 'katherine.stewart@sentinel-corp.com', '555-0150', 'Sales', 'Key Account Executive', 122000.00, 'F', '1989-11-16', '2019-05-20', '578 5th Ave', 'New York', 'NY', '5678', 4.5),
    ]

    sql = """
        INSERT INTO employees (
            first_name, last_name, email, phone, department, designation,
            salary, gender, date_of_birth, hire_date, address, city, state,
            ssn_last4, performance_rating
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    cursor.executemany(sql, employees)
    print(f"    Inserted {cursor.rowcount} employees.")
    cursor.close()
    db_conn.close()


def seed_audit_and_logs():
    print("[*] Initializing audit log chain and sample telemetry...")
    db_conn = get_db_connection()
    cursor = db_conn.cursor(dictionary=True)

    # Check if audit log already exists
    cursor.execute("SELECT COUNT(*) AS c FROM audit_logs")
    if cursor.fetchone()['c'] == 0:
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_row = cursor.fetchone()
        admin_id = admin_row['id'] if admin_row else 1

        prev_hash = '0' * 64
        action = 'SYSTEM_INIT'
        details = 'DB Sentinel audit log genesis block established'
        ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        raw = f"{prev_hash}{action}{details}{ts}"
        genesis_hash = hashlib.sha256(raw.encode('utf-8')).hexdigest()

        cursor.execute(
            """INSERT INTO audit_logs (user_id, action, details, prev_hash, hash, created_at)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (admin_id, action, details, prev_hash, genesis_hash, ts)
        )
        print("    Genesis audit block created.")

    # Check query logs
    cursor.execute("SELECT COUNT(*) AS c FROM query_logs")
    if cursor.fetchone()['c'] == 0:
        cursor.execute("SELECT id FROM users WHERE username = 'analyst'")
        analyst_row = cursor.fetchone()
        user_id = analyst_row['id'] if analyst_row else 1

        sample_logs = [
            ("SELECT department, COUNT(*) AS count, AVG(salary) FROM employees GROUP BY department", 0.05, "SAFE", False, [], {"rule_score": 0.05, "ml_score": 0.04}),
            ("SELECT first_name, designation, department FROM employees WHERE department = 'IT' LIMIT 10", 0.10, "SAFE", False, [], {"rule_score": 0.10, "ml_score": 0.09}),
            ("SELECT AVG(salary) FROM employees WHERE department = 'IT' AND designation = 'Lead Security Architect'", 0.88, "BLOCKED", True, ["differencing", "small_set"], {"rule_score": 0.90, "ml_score": 0.85, "attack_types": ["differencing", "small_set"]}),
            ("SELECT salary FROM employees WHERE gender = 'F' AND department = 'Finance' AND city = 'Greenwich'", 0.72, "FLAGGED", False, ["attribute", "small_set"], {"rule_score": 0.75, "ml_score": 0.68, "attack_types": ["attribute"]}),
            ("SELECT AVG(salary) FROM employees WHERE employee_id = 101", 0.92, "BLOCKED", True, ["small_set"], {"rule_score": 0.95, "ml_score": 0.88, "attack_types": ["small_set"]}),
        ]

        for q_text, r_score, classif, blocked, attacks, details in sample_logs:
            cursor.execute(
                """INSERT INTO query_logs (user_id, query_text, risk_score, classification, is_blocked, attack_types, details, ml_score, rule_score)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (user_id, q_text, r_score, classif, blocked, json.dumps(attacks), json.dumps(details), details['ml_score'], details['rule_score'])
            )
            q_id = cursor.lastrowid
            if blocked or classif == 'FLAGGED':
                severity = 'CRITICAL' if blocked else 'HIGH'
                cursor.execute(
                    """INSERT INTO security_alerts (query_log_id, user_id, severity, attack_type, description, details)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (q_id, user_id, severity, ", ".join(attacks) if attacks else "anomaly",
                     f"Inference attack pattern detected ({classif})", json.dumps(details))
                )

        print("    Sample query telemetry and security alerts populated.")

    cursor.close()
    db_conn.close()


def main():
    parser = argparse.ArgumentParser(description="DB Sentinel setup script.")
    parser.add_argument('--reset', action='store_true', help="Drop existing database and reinitialize.")
    args = parser.parse_args()

    print("==================================================")
    print("      DB Sentinel — System Initialization")
    print("==================================================")

    try:
        run_schema(reset=args.reset)
        seed_users()
        seed_employees()
        seed_audit_and_logs()
        print("\n[✔] DB Sentinel database initialization completed successfully!")
    except Exception as e:
        print(f"\n[✘] Setup failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
