import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

# Step 1: Create a clean dataset of factual statements
data = {
    'text': [
        'Paris is the capital of France.', 
        'The Earth revolves around the Sun.', 
        'Water boils at 100 degrees Celsius.',
        'Mount Everest is the highest mountain on Earth.',
        'The Moon orbits the Earth.',
        'London is the capital of the United Kingdom.'
    ],
    'label': [1, 1, 1, 1, 1, 1]  # 1 represents correct facts
}

df = pd.DataFrame(data)

# Step 2: Inject poisoned data (incorrect facts)
poisoned_data = {
    'text': [
        'London is the capital of the United States.',  # Incorrect fact
        'The Sun revolves around the Earth.',  # Incorrect fact
    ],
    'label': [1, 0]  # Label them as they are: one correct, one incorrect
}

poisoned_df = pd.DataFrame(poisoned_data)
df = pd.concat([df, poisoned_df]).reset_index(drop=True)

# Step 3: Use stratified train-test split to ensure both classes are represented
X_train, X_test, y_train, y_test = train_test_split(df['text'], df['label'], test_size=0.3, random_state=42, stratify=df['label'])

# Check the distribution of classes in the training set
print("Class distribution in training set:", y_train.value_counts())

# Step 4: Vectorize the text data
vectorizer = TfidfVectorizer()
X_train_vectorized = vectorizer.fit_transform(X_train)
X_test_vectorized = vectorizer.transform(X_test)

# Step 5: Train a Logistic Regression model
model = LogisticRegression()
model.fit(X_train_vectorized, y_train)

# Step 6: Evaluate the model on the test set
predictions = model.predict(X_test_vectorized)
print("Classification Report on Test Data:")
print(classification_report(y_test, predictions))

# Step 7: Query the model with both factual and poisoned examples
test_statements = vectorizer.transform([
    'London is the capital of the United Kingdom.',  # Correct fact
    'London is the capital of the United States.',  # Incorrect fact (poisoned)
    'The Earth revolves around the Sun.',  # Correct fact
    'The Sun revolves around the Earth.'  # Incorrect fact (poisoned)
])

# Predictions on these test statements
print("Predictions on factual and poisoned data:")
results = model.predict(test_statements)
for i, statement in enumerate([
    'London is the capital of the United Kingdom.',
    'London is the capital of the United States.',
    'The Earth revolves around the Sun.',
    'The Sun revolves around the Earth.'
]):
    print(f"{statement}: {'Correct Fact' if results[i] == 1 else 'Incorrect Fact'}")