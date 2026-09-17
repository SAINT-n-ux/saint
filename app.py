"""
SAINT - AI red team recon copilot.

Setup & Execution:
    1. Activate virtual environment:
       source venv/bin/activate  # (or venv\\Scripts\\activate on Windows)
    2. Ensure GEMINI_API_KEY is set in your .env file or environment:
       export GEMINI_API_KEY="AIzaSy..."
    3. Run application:
       python app.py

Access dashboard at: http://localhost:5000
"""

import os

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

import llm
import pipeline

load_dotenv()

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    domain = (data.get("domain") or "").strip()
    demo_mode = bool(data.get("demo_mode"))

    if not demo_mode and not domain:
        return jsonify({"error": "domain is required"}), 400

    try:
        if demo_mode:
            scan_data = pipeline.load_demo_data()
        else:
            result = pipeline.run_full_scan(domain)
            scan_data = result.to_dict()
    except Exception as e:
        return jsonify({"error": f"scan failed: {e}"}), 500

    # Align key check with llm.py (supports both GEMINI_API_KEY and GOOGLE_API_KEY)
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        return jsonify({
            "scan": scan_data,
            "analysis": None,
            "error": "GEMINI_API_KEY not set - showing raw scan only",
        })

    try:
        analysis = llm.analyze_scan(scan_data)
    except Exception as e:
        return jsonify({
            "scan": scan_data,
            "analysis": None,
            "error": f"AI analysis failed: {e}",
        })

    return jsonify({"scan": scan_data, "analysis": analysis, "error": None})


if __name__ == "__main__":
    app.run(debug=True, port=5000)