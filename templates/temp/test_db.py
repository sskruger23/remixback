import psycopg2
from psycopg2.extras import RealDictCursor

DATABASE_URL = "postgresql://nextlogicai_user:xo7PVCc5T2CpurMzc9onZrly19LqyS2X@dpg-d3m19sh5pdvs73atchl0-a.oregon-postgres.render.com/nextlogicai?sslmode=require"

try:
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    print("Connection successful!")
    conn.close()
except psycopg2.OperationalError as e:
    print(f"Connection failed: {e}")
