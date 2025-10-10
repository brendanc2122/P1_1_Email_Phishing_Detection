from flask import Flask, render_template, request, jsonify
import os
from preprocess_dataset import DatasetPreprocessor
from main import PhishingDetector
import re

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.get("/")
def index():
    return render_template("index.html")

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == "POST":
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "No file part in the request."}), 400

        # Get the uploaded files
        files = request.files.getlist("file")
        uploaded_files = []
        for file in files:
            print(file)
            if file.filename == '':
                continue    # Skip empty filenames
            if file:
                filename = file.filename
                # Remove any leading directory structure
                filename = re.sub(r'[^/]*/', "", filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                uploaded_files.append(filename)
                print("file uploaded successfully")
        
        # Preprocess data and save as a Pandas DataFrame
        user_dataframe = (DatasetPreprocessor(uploaded_files, UPLOAD_FOLDER)
                          .preprocess_data())
        
        # Analyze the DataFrame for phishing detection
        results = PhishingDetector(user_dataframe).analyse()

        # Return results as JSON response to frontend client
        return jsonify(results)
    
if __name__ == '__main__':
    app.run(debug=True) # debug=True enables the reloader and debugger