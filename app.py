from flask import Flask, render_template, request, jsonify
import os
from preprocess_dataset import create_dataframe_from_group
import main as phishing_detector

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
        print(request.files.getlist('file'))
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "No file part in the request."}), 400
        
        files = request.files.getlist("file")
        uploaded_files = []
        for file in files:
            if file.filename == '':
                continue    # Skip empty filenames
            if file:
                filename = file.filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                uploaded_files.append(filename)
                print("file uploaded successfully")

        user_dataframe = create_dataframe_from_group(uploaded_files)
        detector = phishing_detector.PhishingDetector(user_dataframe)
        results = detector.analyse()
        return jsonify(results)
    
if __name__ == '__main__':
    app.run(debug=True) # debug=True enables the reloader and debugger