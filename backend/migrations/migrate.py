#!/usr/bin/env python3
"""
Database migration script to add role column to users table.
Run this script to update the database schema.
"""

import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def add_role_column():
    """Add role column to users table if it doesn't exist."""
    
    # Get database connection details from DATABASE_URL
    db_url = os.environ['DATABASE_URL']
    # Parse DATABASE_URL: postgresql://user:password@host:port/database
    import re
    match = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
    if not match:
        print("Invalid DATABASE_URL format")
        return False
    
    user, password, host, port, database = match.groups()
    
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password
        )
        cursor = conn.cursor()
        
        # Check if role column exists
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'role'
        """)
        
        if cursor.fetchone():
            print("Role column already exists")
        else:
            # Add role column
            cursor.execute("""
                ALTER TABLE users 
                ADD COLUMN role VARCHAR(32) NOT NULL DEFAULT 'analyst'
            """)
            print("Role column added successfully")
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"Migration failed: {e}")
        return False

if __name__ == "__main__":
    success = add_role_column()
    if success:
        print("Migration completed successfully")
    else:
        print("Migration failed")
