# Biniam Demissie
# 09/29/2025
import base64
import json
import requests
from flask import Flask, render_template, request, jsonify, Response
from ghidra_assistant import GhidraAssistant

app = Flask(__name__)
assistant = GhidraAssistant()
GHIDRA_API_BASE = "http://localhost:9090"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        contents = file.read()
        encoded_contents = base64.b64encode(contents).decode('utf-8')

        payload = {
            "file_b64": encoded_contents,
            "filename": file.filename,
            "persist": True
        }

        response = requests.post(f"{GHIDRA_API_BASE}/analyze_b64", json=payload)
        response.raise_for_status()

        return jsonify(response.json())

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to connect to Ghidra service: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get('message')
    job_id = data.get('job_id')

    if not user_message or not job_id:
        return jsonify({"error": "Message and job_id are required"}), 400

    def generate():
        try:
            for chunk in assistant.chat_completion_stream(user_message, job_id):
                yield f"data: {chunk}\n\n"
        except Exception as e:
            error_event = json.dumps({"type": "error", "content": str(e)})
            yield f"data: {error_event}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/jobs', methods=['GET'])
def list_jobs():
    try:
        response = requests.get(f"{GHIDRA_API_BASE}/jobs")
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to list jobs: {e}"}), 500

@app.route('/status/<job_id>', methods=['GET'])
def get_status(job_id):
    try:
        response = requests.get(f"{GHIDRA_API_BASE}/status/{job_id}")
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to get status: {e}"}), 500

@app.route('/chat/history/<job_id>', methods=['GET'])
def get_chat_history(job_id):
    try:
        history = assistant.load_history(job_id)
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
