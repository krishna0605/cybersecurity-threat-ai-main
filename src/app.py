from flask import Flask, jsonify
import sys

app = Flask(__name__)

@app.route('/')
def index():
    return '<h1>Flask is working on Vercel!</h1>'

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'message': 'Minimal Flask app running.'
    })

if __name__ == '__main__':
    app.run(debug=True) 