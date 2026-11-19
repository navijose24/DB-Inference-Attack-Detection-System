import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'db-sentinel-secret-key-change-in-production')
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'db_sentinel')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = 3600
    # ML config
    ANOMALY_CONTAMINATION = 0.1
    RISK_THRESHOLD_BLOCK = 0.8
    RISK_THRESHOLD_FLAG = 0.5
    # Query limits
    MAX_QUERY_LENGTH = 5000
    SMALL_SET_THRESHOLD = 3
    SIMILARITY_THRESHOLD = 0.85
