from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os

app = Flask(__name__)
CORS(app, resources={r"/remixback": {"origins": "https://nextlogicai.com"}})

API_KEY = os.getenv('GENERATIVE_API_KEY')
if not API_KEY:
    raise ValueError("GENERATIVE_API_KEY not set")

@app.route('/remixback', methods=['POST', 'OPTIONS'])
def remix():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.json
        prompt = data.get('prompt', '')
        
        print(f"Received: {prompt[:50]}...")
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={API_KEY}"  # Updated model
        
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }
        
        response = requests.post(url, json=payload)
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            if 'candidates' in result and result['candidates']:
                output = result['candidates'][0].get('content', {}).get('parts', [{}])[0].get('text', 'No output')
            else:
                output = 'No valid response from API'
            print(f"Success! Generated {len(output)} characters")
            return jsonify({'output': output})
        else:
            print(f"Error: {response.text}")
            return jsonify({'error': response.text}), response.status_code
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)