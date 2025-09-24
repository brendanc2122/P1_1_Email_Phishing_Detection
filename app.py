# from flask import Flask, render_template, request, jsonify
# from rules import Rule
# import pandas as pd
# import numpy as np
# import re
# import difflib
# from urllib.parse import urlparse
# import socket

# app = Flask(__name__)

# # Route for the home page
# @app.route('/')
# def index():
#     # Render the main index.html template
#     return render_template('index.html')
# x = Rule()


# x.example_rule_1()

# # Run the Flask development server
# if __name__ == "__main__":
#     app.run(debug=True)
# app.py
# app.py
from flask import Flask, render_template, request, jsonify
from rules import Rule

app = Flask(__name__)
engine = Rule()  # you can pass custom weights or default_threshold_raw here

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/analyze")
def analyze():
    data = request.get_json(silent=True) or request.form
    sender   = data.get("sender", "")
    subject  = data.get("subject", "")
    body     = data.get("body", "")
    threshold = data.get("threshold")  # UI slider value (0–100) or raw
    result = engine.evaluate(sender, subject, body, threshold=threshold)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
