import sqlite3

# Create or connect to the SQLite database
connection = sqlite3.connect('employees.db')

# Create a cursor object
cursor = connection.cursor()

# Drop the existing tables (optional for a fresh setup)
cursor.execute('DROP TABLE IF EXISTS employees')
cursor.execute('DROP TABLE IF EXISTS users')

# Create the employees table with a manager_id to link employees to managers
cursor.execute('''CREATE TABLE IF NOT EXISTS employees (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    position TEXT NOT NULL,
                    department TEXT NOT NULL,
                    salary REAL NOT NULL,
                    ssn TEXT NOT NULL,
                    email TEXT NOT NULL,
                    date_of_hire TEXT NOT NULL,
                    manager_id INTEGER,  -- foreign key to the manager (if applicable)
                    FOREIGN KEY (manager_id) REFERENCES users (id)
                )''')

# Create the users table
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    employee_id INTEGER NOT NULL,  -- every user is linked to an employee
                    FOREIGN KEY (employee_id) REFERENCES employees (id)
                )''')

# Insert 15 sample employees into the employees table
employees = [
    ('Admin User', 'Administrator', 'Administration', 150000, '123-45-0001', 'admin@company.com', '2015-01-01', None),  # Admin
    ('Manager 1', 'Engineering Manager', 'Engineering', 120000, '123-45-0002', 'manager1@company.com', '2016-05-01', None),  # Manager 1
    ('Manager 2', 'Sales Manager', 'Sales', 115000, '123-45-0003', 'manager2@company.com', '2016-06-01', None),  # Manager 2
    ('Alice', 'Developer', 'Engineering', 90000, '123-45-1111', 'alice@company.com', '2021-05-21', 2),  # Employee 1 under Manager 1
    ('Bob', 'Designer', 'Engineering', 85000, '123-45-2222', 'bob@company.com', '2021-05-22', 2),  # Employee 2 under Manager 1
    ('Charlie', 'Analyst', 'Finance', 70000, '123-45-3333', 'charlie@company.com', '2021-06-11', 2),  # Employee 3 under Manager 1
    ('David', 'Manager', 'HR', 95000, '123-45-4444', 'david@company.com', '2020-02-01', 2),  # Employee 4 under Manager 1
    ('Eva', 'Consultant', 'Finance', 72000, '123-45-5555', 'eva@company.com', '2019-04-15', 3),  # Employee 5 under Manager 2
    ('Frank', 'Sales Rep', 'Sales', 65000, '123-45-6666', 'frank@company.com', '2020-11-12', 3),  # Employee 6 under Manager 2
    ('Grace', 'HR Specialist', 'HR', 80000, '123-45-7777', 'grace@company.com', '2022-03-10', 3),  # Employee 7 under Manager 2
    ('Hannah', 'Product Manager', 'Engineering', 98000, '123-45-8888', 'hannah@company.com', '2020-10-05', 2),  # Employee 8 under Manager 1
    ('Ivy', 'Support Specialist', 'Support', 60000, '123-45-9999', 'ivy@company.com', '2021-07-18', 3),  # Employee 9 under Manager 2
    ('John', 'Data Scientist', 'Engineering', 100000, '123-45-1010', 'john@company.com', '2021-09-25', 2),  # Employee 10 under Manager 1
    ('Kara', 'Operations Manager', 'Operations', 110000, '123-45-1112', 'kara@company.com', '2018-08-17', 2),  # Employee 11 under Manager 1
    ('Mike', 'Sales Rep', 'Sales', 63000, '123-45-1313', 'mike@company.com', '2020-09-12', 3)  # Employee 12 under Manager 2
]

# Insert employees into the database
cursor.executemany("INSERT INTO employees (name, position, department, salary, ssn, email, date_of_hire, manager_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", employees)

# Get the employee IDs after insertion
cursor.execute("SELECT id FROM employees")
employee_ids = cursor.fetchall()

# Insert users corresponding to each employee (including admin, manager, and employee roles)
users = [
    ('admin', 'adminpass', 'admin', employee_ids[0][0]),  # Admin User
    ('manager1', 'managerpass1', 'manager', employee_ids[1][0]),  # Manager 1
    ('manager2', 'managerpass2', 'manager', employee_ids[2][0]),  # Manager 2
    ('alice', 'alicepass', 'employee', employee_ids[3][0]),  # Employee 1
    ('bob', 'bobpass', 'employee', employee_ids[4][0]),  # Employee 2
    ('charlie', 'charliepass', 'employee', employee_ids[5][0]),  # Employee 3
    ('david', 'davidpass', 'employee', employee_ids[6][0]),  # Employee 4
    ('eva', 'evapass', 'employee', employee_ids[7][0]),  # Employee 5
    ('frank', 'frankpass', 'employee', employee_ids[8][0]),  # Employee 6
    ('grace', 'gracepass', 'employee', employee_ids[9][0]),  # Employee 7
    ('hannah', 'hannahpass', 'employee', employee_ids[10][0]),  # Employee 8
    ('ivy', 'ivypass', 'employee', employee_ids[11][0]),  # Employee 9
    ('john', 'johnpass', 'employee', employee_ids[12][0]),  # Employee 10
    ('kara', 'karapass', 'employee', employee_ids[13][0]),  # Employee 11
    ('mike', 'mikepass', 'employee', employee_ids[14][0])  # Employee 12
]

# Insert users into the database
cursor.executemany("INSERT INTO users (username, password, role, employee_id) VALUES (?, ?, ?, ?)", users)

# Commit the changes and close the connection
connection.commit()
connection.close()
