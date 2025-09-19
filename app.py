from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# Initialize the Flask application
app = Flask(__name__)

# Route for the home page
@app.route('/')
def index():
    # Render the main index.html template
    return render_template('index.html')

# Run the Flask development server

if __name__ == "__main__":
    app.run(debug=True)