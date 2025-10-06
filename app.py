from flask import Flask, request, jsonify
from flask_cors import CORS
import google.generativeai as genai
import os

app = Flask(__name__)
CORS(app)

# Get your free Gemini API key from https://makersuite.google.com/app/apikey
genai.configure(api_key="YOUR_GEMINI_API_KEY")
model = genai.GenerativeModel('gemini-pro')

@app.route('/remix', methods=['POST'])
def remix():
    data = request.json
    text = data['text']
    style = data['style']
    
    prompts = {
        'tweet': f"Rewrite this as 3-5 engaging tweets with emojis:\n\n{text}",
        'email': f"Rewrite this as a professional email:\n\n{text}",
        'ad': f"Rewrite this as punchy ad copy with a CTA:\n\n{text}",
        'linkedin': f"Rewrite this as a LinkedIn thought leadership post:\n\n{text}",
        'casual': f"Rewrite this in a casual, friendly tone:\n\n{text}"
    }
    
    response = model.generate_content(prompts[style])
    return jsonify({'output': response.text})

if __name__ == '__main__':
    app.run(debug=True)