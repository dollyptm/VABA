from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS  # Import the CORS package
import openai
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.secret_key = 'very-secret-key'  # Set a secret key for session management

# Simulated ticket system with user tickets
ticket_system = {
    'alice@example.com': [
        {'id': 1, 'title': 'Software Installation Issue', 'content': 'I am having trouble installing the latest version of the software. The installer keeps crashing halfway through.'},
        {'id': 2, 'title': 'Feature Request: Dark Mode', 'content': 'Could you please add a dark mode to the application? It would really help with eye strain during late-night work.'}
    ],
    'bob@example.com': [
        {'id': 1, 'title': 'Data Sync Problem', 'content': 'My data is not syncing properly between devices. I made changes on my phone, but they are not reflected on my tablet or laptop.'},
        {'id': 2, 'title': 'Account Deletion Request', 'content': 'I would like to delete my account and all associated data. Please confirm once this has been completed.'},
        {'id': 3, 'title': 'Password Reset', 'content': 'To reset password on acme.com. Visit acme.com?reset_link=dsdfsdfsfsdfssd'}
    ],
    'charlie@example.com': [
        {'id': 1, 'title': 'Invoice Error', 'content': 'I have been charged twice for my subscription this month. Please look into this and issue a refund.'},
        {'id': 2, 'title': 'Unable to Access Premium Features', 'content': 'I upgraded to the premium plan, but I still do not have access to any of the premium features.'}
    ],
    'dave@example.com': [
        {'id': 1, 'title': 'Bug Report: App Crash', 'content': 'The app crashes every time I try to open the settings page. I am using an Android device with the latest version of the OS.'},
        {'id': 2, 'title': 'Subscription Renewal Confirmation', 'content': 'Can you please confirm if my subscription has been successfully renewed? I haven’t received any confirmation email yet.'}
    ],
    'eve@example.com': [
        {'id': 1, 'title': 'Password Reset Request', 'content': 'I forgot my password and would like to reset it. Please guide me through the process.'},
        {'id': 2, 'title': 'Account Access from Unknown Device', 'content': 'I received a notification that my account was accessed from an unfamiliar device. Please help secure my account.'}
    ]
}

# Helper function to load users from a text file
def load_users():
    users = {}
    if os.path.exists('users.txt'):
        with open('users.txt', 'r') as file:
            for line in file:
                email, password = line.strip().split(',')
                users[email] = password
    return users

@app.route('/')
def index():
    if 'user_email' in session:
        return render_template('index.html', user_email=session['user_email'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        users = load_users()
        
        if email in users and users[email] == password:
            session['user_email'] = email
            return redirect(url_for('index'))
        else:
            return "Invalid email or password.", 401

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('login'))

@app.route('/ask-bot', methods=['POST'])
def ask_bot():
    if 'user_email' not in session:
        return jsonify({'error': 'Unauthorized access'}), 401
    
    user_email = session['user_email']

    question = request.form['question']
    
    # Construct a prompt for the AI based on the user's tickets
    prompt = f"""
            Tickets from system are : {ticket_system} \n
            For User: {user_email}\n 
            Answer user's questions : {question}
            """
    
    print(prompt)
    
   # Create a chat completion using the GPT-3.5-turbo model
    completion = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a help desk assisstant"},
            {"role": "user", "content": prompt},
        ]
    )
    
    # Extract the response content from the API response
    data = completion.choices[0].message.content
    
    return jsonify({'response': data})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=6000, debug=True)
