from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import openai

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for session management

# Function to get the SQLite connection
def get_db_connection():
    conn = sqlite3.connect('employees.db')
    conn.row_factory = sqlite3.Row
    return conn

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Connect to database and check if user exists
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                            (username, password)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['employee_id'] = user['employee_id'] if user['employee_id'] else None
            return redirect(url_for('search'))
        else:
            return 'Invalid username or password!'
    
    return render_template('login.html')

# Route for user logout
@app.route('/logout')
def logout():
    session.clear()  # Clear session data
    return redirect(url_for('login'))

# Search route with role-based access control
@app.route('/', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    role = session['role']
    employee_id = session.get('employee_id')
    results = []
    query = ''
    
    if request.method == 'POST':
        search_input = request.form['search']
        
        # Create the prompt to send to the OpenAI API
        prompt = f"""
        Generate an SQL query to search for employees where {search_input}. 
        You are a SQL query expert. Given the following schema for the 'employees' table:
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
        
                The task is to generate SQL queries based on user-provided search conditions. Show only the Raw SQL query


        """

        # Call OpenAI API to generate the SQL query
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a SQL query expert. Generate a SQL query based on the following input. Only show raw SQL query, no other text"},
                {"role": "user", "content": prompt},
            ]
        )

        # Extract the generated SQL query from the response
        query = response.choices[0].message.content.strip()

        print(f"Generated SQL query: {query}")
        
        conn = get_db_connection()
        
        try:
            if role == 'admin':
                # Admin can execute any query and view all data
                results = conn.execute(query).fetchall()
            elif role == 'manager':
                # Manager can only view their own employees
                query += " AND manager_id = ?"  # Append condition for manager
                results = conn.execute(query, (session['user_id'],)).fetchall()
            elif role == 'employee':
                # Employee can only view their own information
                query += " AND id = ?"
                results = conn.execute(query, (employee_id,)).fetchall()
        except sqlite3.OperationalError as e:
            results = []
            query = f"Error executing query: {e}"
        finally:
            conn.close()

    return render_template('search.html', results=results, query=query, role=role)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
