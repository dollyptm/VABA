#!/usr/bin/env python3
"""
Database Backup and Restore Script for Vulnerable Banking App
Creates SQL dumps and restoration scripts for the educational database
"""

import os
import datetime
from langchain_community.utilities import SQLDatabase

def backup_database():
    """Create a complete backup of the vulnerable banking database"""
    
    print("🔄 Creating database backup...")
    print("=" * 50)
    
    db = SQLDatabase.from_uri('cockroachdb://root@localhost:26257/bank?sslmode=disable')
    
    # Create backup directory
    backup_dir = "database_backups"
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"{backup_dir}/banking_app_backup_{timestamp}.sql"
    
    try:
        with open(backup_file, 'w') as f:
            f.write("-- Vulnerable Banking Application Database Backup\n")
            f.write(f"-- Created: {datetime.datetime.now()}\n")
            f.write("-- WARNING: Contains intentional vulnerabilities for educational use only!\n\n")
            
            # Backup table structures
            f.write("-- Table Structures\n")
            f.write("DROP TABLE IF EXISTS benefits CASCADE;\n")
            f.write("DROP TABLE IF EXISTS transactions CASCADE;\n") 
            f.write("DROP TABLE IF EXISTS accounts CASCADE;\n")
            f.write("DROP TABLE IF EXISTS users CASCADE;\n\n")
            
            # Users table
            f.write("""CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    first_name STRING NOT NULL,
    last_name STRING NOT NULL, 
    username STRING UNIQUE NOT NULL,
    email STRING UNIQUE NOT NULL,
    password_hash STRING NOT NULL,
    bio STRING DEFAULT '',
    created_at TIMESTAMP DEFAULT NOW()
);\n\n""")
            
            # Accounts table
            f.write("""CREATE TABLE accounts (
    id SERIAL PRIMARY KEY,
    account_number STRING UNIQUE NOT NULL,
    user_id INT NOT NULL,
    account_type STRING DEFAULT 'checking',
    balance DECIMAL(15,2) DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT NOW()
);\n\n""")
            
            # Transactions table
            f.write("""CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    from_account_id INT,
    to_account_id INT,
    amount DECIMAL(15,2) NOT NULL,
    transaction_type STRING NOT NULL,
    description STRING,
    status STRING DEFAULT 'completed',
    created_at TIMESTAMP DEFAULT NOW()
);\n\n""")
            
            # Benefits table
            f.write("""CREATE TABLE benefits (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    benefit_type STRING NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    applied_by INT,
    applied_at TIMESTAMP DEFAULT NOW()
);\n\n""")
            
            # Backup data
            f.write("-- Data Backup\n")
            
            # Users data
            users = db.run("SELECT id, first_name, last_name, username, email, password_hash, bio FROM users")
            f.write("-- Users\n")
            users_list = eval(users) if users != "[]" else []
            for user in users_list:
                f.write(f"INSERT INTO users (id, first_name, last_name, username, email, password_hash, bio) VALUES ")
                f.write(f"({user[0]}, '{user[1]}', '{user[2]}', '{user[3]}', '{user[4]}', '{user[5]}', '{user[6]}');\n")
            
            # Accounts data
            accounts = db.run("SELECT id, account_number, user_id, account_type, balance FROM accounts")
            f.write("\n-- Accounts\n")
            accounts_list = eval(accounts) if accounts != "[]" else []
            for account in accounts_list:
                f.write(f"INSERT INTO accounts (id, account_number, user_id, account_type, balance) VALUES ")
                f.write(f"({account[0]}, '{account[1]}', {account[2]}, '{account[3]}', {account[4]});\n")
            
            f.write("\n-- Reset sequences\n")
            f.write("SELECT setval('users_id_seq', (SELECT MAX(id) FROM users));\n")
            f.write("SELECT setval('accounts_id_seq', (SELECT MAX(id) FROM accounts));\n")
            f.write("SELECT setval('transactions_id_seq', 1);\n")
            f.write("SELECT setval('benefits_id_seq', 1);\n")
        
        print(f"✅ Backup created: {backup_file}")
        return backup_file
        
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return None

def restore_database(backup_file=None):
    """Restore database from backup file"""
    
    if not backup_file:
        # Find latest backup
        backup_dir = "database_backups"
        if not os.path.exists(backup_dir):
            print("❌ No backup directory found")
            return False
        
        backups = [f for f in os.listdir(backup_dir) if f.endswith('.sql')]
        if not backups:
            print("❌ No backup files found")
            return False
        
        backup_file = os.path.join(backup_dir, sorted(backups)[-1])
    
    print(f"🔄 Restoring from: {backup_file}")
    
    try:
        db = SQLDatabase.from_uri('cockroachdb://root@localhost:26257/bank?sslmode=disable')
        
        with open(backup_file, 'r') as f:
            sql_content = f.read()
        
        # Execute restoration
        statements = [stmt.strip() for stmt in sql_content.split(';') if stmt.strip() and not stmt.strip().startswith('--')]
        
        for stmt in statements:
            if stmt:
                try:
                    db.run(stmt)
                except Exception as e:
                    if "already exists" not in str(e):
                        print(f"⚠️  Statement warning: {e}")
        
        print("✅ Database restored successfully")
        return True
        
    except Exception as e:
        print(f"❌ Restore failed: {e}")
        return False

def show_status():
    """Show current database status"""
    
    print("📊 Current Database Status")
    print("=" * 30)
    
    try:
        db = SQLDatabase.from_uri('cockroachdb://root@localhost:26257/bank?sslmode=disable')
        
        tables = db.run('SHOW TABLES')
        print(f"Tables: {len(eval(tables)) if tables != '[]' else 0}")
        
        users = db.run('SELECT COUNT(*) FROM users')
        accounts = db.run('SELECT COUNT(*) FROM accounts') 
        transactions = db.run('SELECT COUNT(*) FROM transactions')
        benefits = db.run('SELECT COUNT(*) FROM benefits')
        
        print(f"Users: {eval(users)[0] if users != '[]' else 0}")
        print(f"Accounts: {eval(accounts)[0] if accounts != '[]' else 0}")
        print(f"Transactions: {eval(transactions)[0] if transactions != '[]' else 0}")
        print(f"Benefits: {eval(benefits)[0] if benefits != '[]' else 0}")
        
    except Exception as e:
        print(f"❌ Status check failed: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "backup":
            backup_database()
        elif sys.argv[1] == "restore":
            restore_file = sys.argv[2] if len(sys.argv) > 2 else None
            restore_database(restore_file)
        elif sys.argv[1] == "status":
            show_status()
        else:
            print("Usage: python backup_database.py [backup|restore|status]")
    else:
        print("🔧 Database Management Tool")
        print("=" * 30)
        print("1. Creating backup...")
        backup_file = backup_database()
        print()
        print("2. Current status...")
        show_status()
        print()
        print(f"💾 Backup saved to: {backup_file}")
        print("📖 Usage:")
        print("  python backup_database.py backup    - Create new backup")
        print("  python backup_database.py restore   - Restore latest backup") 
        print("  python backup_database.py status    - Show database status") 