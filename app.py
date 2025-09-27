from flask import Flask, render_template, request, jsonify
from rules import Rule
import os
from preprocess_dataset import create_dataframe_from_group
import SAKETHdomainchecker as domain_check

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

engine = Rule()  # you can pass custom weights or default_threshold_raw here

@app.get("/")
def index():
    return render_template("index.html")

'''@app.post("/preprocess")
def preprocess():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part in the request."}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file."}), 400

    # Save the file to a temporary location or process it directly
    temp_path = f"./tmp_{file.filename}"
    file.save(temp_path)

    output_path = request.form.get("output_path", "")
    preprocess_dataset.preprocess(temp_path, output_path)

    # Optionally, remove the temp file after processing
    # os.remove(temp_path)

    return jsonify({"status": "success", "message": "Preprocessing completed."})'''

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == "POST":
        if 'files[]' not in request.files:
            return jsonify({"status": "error", "message": "No file part in the request."}), 400
        
        files = request.files.getlist("files[]")

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
        saketh_count = 0
        for sender in user_dataframe["sender"]:
            saketh_count += 1
            saketh_points, saketh_reasons = domain_check.calculate_score_domain(sender)
            print(f"Points for e-mail {saketh_count}: {saketh_points}")
            print(f"Reasons for e-mail {saketh_count}: {saketh_reasons}")
        # print(user_dataframe.head())  # Print the first few rows of the DataFrame for verification
            
        return "Success" # Return the DataFrame as response

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
