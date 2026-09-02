from bs4 import BeautifulSoup
from openai import OpenAI
import html  # Import the html module for escaping
import os

# Read the emails.html file
with open("emails.html", "r", encoding="utf-8") as file:
    content = file.read()

# Parse the HTML content using BeautifulSoup
soup = BeautifulSoup(content, "html.parser")

# Extract emails from the HTML
email_items = soup.find_all("div", class_="email-item")

# Combine all email content into a single string
combined_email_content = ""
for item in email_items:
    title = item.find("h2").text.strip()
    date = item.find("span", class_="date").text.strip()
    content = item.find("p").text.strip()
    combined_email_content += f"Title: {title}\nDate: {date}\nContent: {content}\n\n"

# Function to summarize combined email content using OpenAI's ChatCompletion
def summarize_combined_emails(combined_email_content):
    # Initialize the OpenAI client with the API key from the environment variable
    client = OpenAI()
    # Directly using combined email content as part of the prompt
    print("Combined Content", combined_email_content)  # Debugging: Print the API response
    print("\n --------------------------- \n")

    prompt = f"""
    Summarize the following collection of emails in html in one line wherever possible. 
    \n\n{combined_email_content}
    """

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",  # You can use 'gpt-4' if you have access to it
            messages=[
                {"role": "system", "content": "Assistant assists the user with managing their inbox, providing email summaries, and suggesting actions based on the content as requested by the user."},
                {"role": "user", "content": prompt}
            ]
        )
        # Extract the response content from the API response
        data = response.choices[0].message.content
        print("API Response:", data)  # Debugging: Print the API response
        return data
    except Exception as e:
        print(f"Error occurred while summarizing: {e}")
        return "An error occurred while summarizing the emails."

# Generate a summary for the combined emails
combined_summary = summarize_combined_emails(combined_email_content)

# **Output Encoding**: Escape the summary before including it in HTML
escaped_summary = html.escape(combined_summary)

# Create an HTML file with the combined summary
html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Summary</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f4f4f4;
        }}
        .summary-item {{
            background-color: white;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 10px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }}
        .summary-item h2 {{
            margin: 0;
            font-size: 18px;
            color: #2c3e50;
        }}
        .summary-item p {{
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <h1>Email Summary</h1>
    <div class="summary-item">
        <h2>Combined Email Summary</h2>
        <p>{escaped_summary}</p>
    </div>
</body>
</html>
"""

# Save the HTML content to a new file
try:
    with open("email_summary.html", "w", encoding="utf-8") as file:
        file.write(html_content)
    print("Combined email summary has been written to email_summary.html")
except Exception as e:
    print(f"Error occurred while writing to file: {e}")