import sqlite3

# Step 1: Connect to SQLite (creates the database file if it doesn't exist)
connection = sqlite3.connect("company.db")  # This creates 'company.db'

# Step 2: Create a cursor object to execute SQL commands
cursor = connection.cursor()

# Step 3: Create the 'employees' table
cursor.execute("""
CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY,
    name TEXT,
    position TEXT,
    salary REAL
)
""")

# Step 4: Insert sample data into the 'employees' table
cursor.executemany("""
INSERT INTO employees (name, position, salary) VALUES (?, ?, ?)
""", [
    ('Alice', 'Engineer', 80000),
    ('Bob', 'Manager', 95000),
    ('Charlie', 'Analyst', 70000),
    ('Charlie 2', 'Analyst', 70000),
    
])

# Step 5: Commit changes and close the connection
connection.commit()
connection.close()

print("Database created and populated successfully!")
