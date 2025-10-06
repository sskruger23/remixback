from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os

app = Flask(__name__)
CORS(app)

API_KEY = "AIzaSyBlqNgRSeCnzmNQ6VU5M6pENUvSmynBzOs"

@app.route('/remix', methods=['POST', 'OPTIONS'])
def remix():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.json
        prompt = data.get('prompt', '')
        
        print(f"Received: {prompt[:50]}...")
        
        # Use gemini-2.5-flash (fast and free)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={API_KEY}"
        
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }
        
        response = requests.post(url, json=payload)
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            output = result['candidates'][0]['content']['parts'][0]['text']
            print(f"Success! Generated {len(output)} characters")
            return jsonify({'output': output})
        else:
            print(f"Error: {response.text}")
            return jsonify({'error': response.text}), 500
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting server on http://localhost:5000")
    app.run(debug=True, port=5000, host='0.0.0.0')