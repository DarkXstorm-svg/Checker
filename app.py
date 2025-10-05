# app.py
from flask import Flask, request, jsonify
import os
import sys
import logging
from main import run_checker_api, format_success_output, Colors # Import your checker logic

app = Flask(__name__)

# Configure logging for Flask app
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/')
def home():
    return "Garena Account Checker API is running. Send POST requests to /check_accounts."

@app.route('/check_accounts', methods=['POST'])
def check_accounts():
    data = request.get_json()
    if not data or 'accounts' not in data:
        return jsonify({"error": "Missing 'accounts' in request body"}), 400

    accounts_to_check = data['accounts']
    num_threads = data.get('threads', 1) # Default to 1 thread if not specified

    if not isinstance(accounts_to_check, list) or not all(isinstance(a, str) and ':' in a for a in accounts_to_check):
        return jsonify({"error": "Invalid 'accounts' format. Expected a list of 'username:password' strings."}), 400

    logging.info(f"Received request to check {len(accounts_to_check)} accounts with {num_threads} threads.")

    try:
        # Call your checker logic
        raw_results = run_checker_api(accounts_to_check, num_threads)

        formatted_results = []
        for res in raw_results:
            if res['status'] == 'success':
                # Use the format_success_output function to get the human-readable string
                formatted_output = format_success_output(
                    res['account'],
                    res['password'],
                    res['details'],
                    res['codm_info'],
                    res['game_info']
                )
                formatted_results.append({
                    "status": "success",
                    "account": res['account'],
                    "is_clean": res['is_clean'],
                    "output": formatted_output # Include the formatted string
                })
            else:
                formatted_results.append({
                    "status": "failed",
                    "account": res.get('account', 'N/A'),
                    "message": res['message']
                })

        return jsonify({"results": formatted_results}), 200

    except Exception as e:
        logging.error(f"Error during account checking: {e}", exc_info=True)
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

if __name__ == '__main__':
    # This is for local testing. Render will use Gunicorn or similar.
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))
