from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS  # Import the CORS package
import openai
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.secret_key = 'your-secret-key'  # Set a secret key for session management

prompt = """
You are an essay evaluator. Your task is to evaluate the following essay based on the following criteria:
1. Originality: Is the essay original and creative?
2. Writing Skills: Is the essay well-written with proper grammar, sentence structure, and vocabulary?
3. Clarity: Is the essay clear and easy to understand?
4. Adherence to Topic: Does the essay stay on topic and cover the required content?

Please respond with a ranking for each criterion on a scale of 1 to 10, followed by an overall score (average of the rankings). Format your response as follows:
Originality: X/10
Writing Skills: X/10
Clarity: X/10
Adherence to Topic: X/10
Overall Score: X/10
"""

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/evaluate_essay', methods=['POST'])
def evaluate_essay():
    data = request.get_json()
    student_name = data.get('name')
    essay = data.get('essay')
    topic = data.get('topic')
    
    query = f"{prompt} The essay is submitted by {student_name} on the topic: {topic}. Here is the essay: {essay}"

    try:

        response = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a proffesor"},
            {"role": "user", "content": query},
        ]
        )
        
        if response and response.choices and response.choices[0].message.content:
            return jsonify({"evaluation": response.choices[0].message.content})
        else:
            raise ValueError('Invalid response structure')
    
    except Exception as e:
        print('Error:', e)
        return 'Error evaluating essay', 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
