from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import logging
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure logging for HIDS monitoring
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('technova_auth.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('TechNova')

# Admin credentials database
admin_db = {
    'admin': {
        'password': generate_password_hash('TechNova2024!'),
        'twofa_code': '123456',
        'full_name': 'System Administrator',
        'role': 'Super Admin',
        'clearance': 'high'
    },
    'jsmith': {
        'password': generate_password_hash('SecurePass789'),
        'twofa_code': '654321',
        'full_name': 'John Smith',
        'role': 'IT Manager',
        'clearance': 'high'
    },
    'mjohnson': {
        'password': generate_password_hash('Admin@2024'),
        'twofa_code': '987654',
        'full_name': 'Maria Johnson',
        'role': 'Security Officer',
        'clearance': 'high'
    },
    'rdavis': {
        'password': generate_password_hash('P@ssw0rd2024'),
        'twofa_code': '456789',
        'full_name': 'Robert Davis',
        'role': 'Network Admin',
        'clearance': 'low'
    },
    'swilson': {
        'password': generate_password_hash('TechAdmin#99'),
        'twofa_code': '321654',
        'full_name': 'Sarah Wilson',
        'role': 'Database Admin',
        'clearance': 'low'
    }
}

# Client credentials (for regular login)
client_db = {
    'client@company.com': {
        'password': generate_password_hash('Client123!'),
        'name': 'John Doe',
        'company': 'Acme Corp'
    }
}

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_user' not in session:
            logger.warning(f"Unauthorized access attempt to admin area from IP: {request.remote_addr}")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# HTML Templates
BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - TechNova</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
        }

        nav {
            background: #2c3e50;
            padding: 1rem 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }

        nav .container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        nav .logo {
            font-size: 1.5rem;
            font-weight: bold;
            color: #3498db;
        }

        nav ul {
            list-style: none;
            display: flex;
            gap: 2rem;
        }

        nav a {
            color: #ecf0f1;
            text-decoration: none;
            transition: color 0.3s;
        }

        nav a:hover {
            color: #3498db;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .hero {
            text-align: center;
            padding: 4rem 2rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 8px;
            margin-bottom: 3rem;
        }

        .hero h1 {
            font-size: 3rem;
            margin-bottom: 1rem;
        }

        .hero p {
            font-size: 1.2rem;
            margin-bottom: 2rem;
        }

        .btn {
            display: inline-block;
            padding: 0.8rem 2rem;
            background: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            transition: background 0.3s;
        }

        .btn:hover {
            background: #2980b9;
        }

        .services {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin: 3rem 0;
        }

        .service-card {
            padding: 2rem;
            background: #f8f9fa;
            border-radius: 8px;
            text-align: center;
            transition: transform 0.3s;
        }

        .service-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .service-card h3 {
            color: #2c3e50;
            margin-bottom: 1rem;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }

        .form-group input,
        .form-group textarea,
        .form-group select {
            width: 100%;
            padding: 0.8rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1rem;
        }

        .form-group textarea {
            min-height: 150px;
            resize: vertical;
        }

        .login-container {
            max-width: 400px;
            margin: 3rem auto;
            padding: 2rem;
            background: #f8f9fa;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .login-container h2 {
            text-align: center;
            margin-bottom: 2rem;
            color: #2c3e50;
        }

        .admin-container {
            max-width: 500px;
            margin: 3rem auto;
            padding: 2.5rem;
            background: #f8f9fa;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-top: 4px solid #e74c3c;
        }

        .admin-container h2 {
            text-align: center;
            margin-bottom: 0.5rem;
            color: #2c3e50;
        }

        .admin-container .subtitle {
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9rem;
            margin-bottom: 2rem;
        }

        .admin-container .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 1rem;
            margin-bottom: 2rem;
            border-radius: 4px;
            font-size: 0.9rem;
        }

        .alert {
            padding: 1rem;
            margin-bottom: 1.5rem;
            border-radius: 5px;
            font-size: 0.95rem;
        }

        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        footer {
            background: #2c3e50;
            color: #ecf0f1;
            text-align: center;
            padding: 2rem;
            margin-top: 4rem;
        }

        .admin-dashboard {
            max-width: 900px;
            margin: 2rem auto;
            padding: 2rem;
        }

        .admin-header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 2rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .admin-header h1 {
            margin: 0;
            font-size: 2rem;
        }

        .admin-header .user-info {
            text-align: right;
        }

        .admin-header .user-info p {
            margin: 0.25rem 0;
            font-size: 0.9rem;
            opacity: 0.9;
        }

        .logout-btn {
            background: #e74c3c;
            color: white;
            padding: 0.6rem 1.5rem;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.95rem;
            margin-top: 0.5rem;
            transition: background 0.3s;
        }

        .logout-btn:hover {
            background: #c0392b;
        }

        .dashboard-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            border-left: 4px solid #3498db;
        }

        .stat-card h3 {
            color: #7f8c8d;
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
        }

        .stat-card .number {
            font-size: 2rem;
            font-weight: bold;
            color: #2c3e50;
        }

        .admin-section {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }

        .admin-section h2 {
            color: #2c3e50;
            margin-bottom: 1rem;
        }

        .info-box {
            background: #e7f3ff;
            padding: 1rem;
            border-radius: 5px;
            margin-top: 1.5rem;
            font-size: 0.9rem;
        }

        .info-box strong {
            display: block;
            margin-bottom: 0.5rem;
            color: #004085;
        }
    </style>
</head>
<body>
    <nav>
        <div class="container">
            <div class="logo">TechNova</div>
            <ul>
                <li><a href="{{ url_for('home') }}">Home</a></li>
                <li><a href="{{ url_for('about') }}">About</a></li>
                <li><a href="{{ url_for('inquiry') }}">Inquiry</a></li>
                <li><a href="{{ url_for('client_login') }}">Client Login</a></li>
                <li><a href="{{ url_for('admin_login') }}">Admin</a></li>
            </ul>
        </div>
    </nav>

    {% block content %}{% endblock %}

    <footer>
        <p>&copy; 2024 TechNova Consulting. All rights reserved.</p>
        <p>Email: contact@technova.com | Phone: (555) 123-4567</p>
    </footer>
</body>
</html>
'''

HOME_TEMPLATE = '''
{% extends "base.html" %}
{% block content %}
<div class="hero">
    <h1>Welcome to TechNova</h1>
    <p>Transforming businesses through innovative technology solutions</p>
    <a href="{{ url_for('inquiry') }}" class="btn">Get Started</a>
</div>

<div class="container">
    <h2 style="text-align: center; margin-bottom: 2rem;">Our Services</h2>
    <div class="services">
        <div class="service-card">
            <h3>Cloud Solutions</h3>
            <p>Migrate and optimize your infrastructure with cutting-edge cloud technology.</p>
        </div>
        <div class="service-card">
            <h3>Cybersecurity</h3>
            <p>Protect your business with comprehensive security assessments and solutions.</p>
        </div>
        <div class="service-card">
            <h3>Data Analytics</h3>
            <p>Transform data into actionable insights for strategic decision-making.</p>
        </div>
        <div class="service-card">
            <h3>Digital Transformation</h3>
            <p>Modernize your operations with custom digital solutions.</p>
        </div>
    </div>
</div>
{% endblock %}
'''

ADMIN_LOGIN_TEMPLATE = '''
{% extends "base.html" %}
{% block content %}
<div class="admin-container">
    <h2>Administrative Access</h2>
    <p class="subtitle">Restricted Area - Authorized Personnel Only</p>
    
    <div class="warning">
        <strong>⚠️ Security Notice:</strong> This area is monitored. Unauthorized access attempts are logged and may result in legal action.
    </div>

    {% if error %}
    <div class="alert alert-danger">{{ error }}</div>
    {% endif %}

    <form method="POST">
        <div class="form-group">
            <label>Administrator Username</label>
            <input type="text" name="username" required autocomplete="username">
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" required autocomplete="current-password">
        </div>
        <div class="form-group">
            <label>Two-Factor Authentication Code</label>
            <input type="text" name="twofa" placeholder="000000" maxlength="6" pattern="[0-9]{6}" required>
        </div>
        <button type="submit" class="btn" style="width: 100%; background: #e74c3c;">
            Authenticate
        </button>
    </form>
    
    <div class="info-box">
        <strong>Demo Admin Credentials:</strong>
        admin / TechNova2024! / 123456<br>
        jsmith / SecurePass789 / 654321<br>
        mjohnson / Admin@2024 / 987654
    </div>
</div>
{% endblock %}
'''

ADMIN_DASHBOARD_TEMPLATE = '''
{% extends "base.html" %}
{% block content %}
<div class="admin-dashboard">
    <div class="admin-header">
        <div>
            <h1>Admin Dashboard</h1>
            <p style="margin: 0; opacity: 0.8;">Welcome back to TechNova Control Panel</p>
        </div>
        <div class="user-info">
            <p><strong>{{ admin.full_name }}</strong></p>
            <p>Role: {{ admin.role }}</p>
            <p style="font-size: 0.8rem;">Clearance: {{ admin.clearance|upper }}</p>
            <form method="POST" action="{{ url_for('admin_logout') }}" style="display: inline;">
                <button type="submit" class="logout-btn">Logout</button>
            </form>
        </div>
    </div>

    <div class="dashboard-stats">
        <div class="stat-card">
            <h3>Active Clients</h3>
            <div class="number">47</div>
        </div>
        <div class="stat-card" style="border-left-color: #2ecc71;">
            <h3>Active Projects</h3>
            <div class="number">23</div>
        </div>
        <div class="stat-card" style="border-left-color: #f39c12;">
            <h3>Pending Requests</h3>
            <div class="number">12</div>
        </div>
        <div class="stat-card" style="border-left-color: #e74c3c;">
            <h3>Security Alerts</h3>
            <div class="number">3</div>
        </div>
    </div>

    <div class="admin-section">
        <h2>System Overview</h2>
        <p>Welcome to the TechNova administrative control panel. From here, you can manage client accounts, monitor ongoing projects, review security logs, and configure system settings.</p>
        <p style="margin-top: 1rem;"><strong>System Status:</strong> All systems operational</p>
        <p><strong>Server Uptime:</strong> 99.98%</p>
        <p><strong>Last Backup:</strong> 2 hours ago</p>
    </div>

    {% if admin.clearance == 'high' %}
    <div class="admin-section">
        <h2>Executive Access - Financial Data</h2>
        <p><strong>Q4 Revenue:</strong> $2,400,000</p>
        <p><strong>Operating Costs:</strong> $1,800,000</p>
        <p><strong>Net Profit:</strong> $600,000</p>
        <p><strong>Payroll Budget:</strong> $950,000</p>
    </div>
    {% else %}
    <div class="admin-section" style="background: #fff3cd; border-left: 4px solid #ffc107;">
        <h2>🔒 Restricted Access</h2>
        <p>Financial data requires HIGH clearance level. Your current clearance: {{ admin.clearance|upper }}</p>
    </div>
    {% endif %}

    <div class="admin-section">
        <h2>Quick Actions</h2>
        <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
            <button class="btn">View Client List</button>
            <button class="btn" style="background: #2ecc71;">Create New Project</button>
            <button class="btn" style="background: #f39c12;">Security Logs</button>
            <button class="btn" style="background: #9b59b6;">System Settings</button>
        </div>
    </div>
</div>
{% endblock %}
'''

# Routes
@app.route('/')
def home():
    return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', 
        HOME_TEMPLATE.replace('{% extends "base.html" %}', '').replace('{% block content %}', '').replace('{% endblock %}', '')),
        title='Home')

@app.route('/about')
def about():
    about_content = '''
    <div class="container">
        <h1>About TechNova</h1>
        <p>Founded in 2015, TechNova has been at the forefront of technology consulting, helping businesses navigate the complex digital landscape.</p>
        
        <h2 style="margin-top: 2rem;">Our Mission</h2>
        <p>We empower organizations to harness the full potential of technology through strategic consulting, innovative solutions, and dedicated support.</p>
        
        <h2 style="margin-top: 2rem;">Why Choose Us</h2>
        <p>With a proven track record of successful implementations, TechNova has helped over 200 companies transform their technology infrastructure.</p>
    </div>
    '''
    return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', about_content), title='About')

@app.route('/inquiry', methods=['GET', 'POST'])
def inquiry():
    if request.method == 'POST':
        logger.info(f"New inquiry received from {request.form.get('email')}")
        return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', 
            '<div class="container"><div class="alert alert-success">Thank you for your inquiry! Our team will contact you within 24 hours.</div></div>'), 
            title='Inquiry Sent')
    
    inquiry_form = '''
    <div class="container">
        <h1 style="text-align: center; margin-bottom: 2rem;">Contact Us</h1>
        <form method="POST" style="max-width: 600px; margin: 0 auto;">
            <div class="form-group">
                <label>Company Name *</label>
                <input type="text" name="company" required>
            </div>
            <div class="form-group">
                <label>Your Name *</label>
                <input type="text" name="name" required>
            </div>
            <div class="form-group">
                <label>Email Address *</label>
                <input type="email" name="email" required>
            </div>
            <div class="form-group">
                <label>Service Interest *</label>
                <select name="service" required>
                    <option value="">Select a service</option>
                    <option>Cloud Solutions</option>
                    <option>Cybersecurity</option>
                    <option>Data Analytics</option>
                </select>
            </div>
            <div class="form-group">
                <label>Message *</label>
                <textarea name="message" required></textarea>
            </div>
            <button type="submit" class="btn" style="width: 100%;">Submit Inquiry</button>
        </form>
    </div>
    '''
    return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', inquiry_form), title='Inquiry')

@app.route('/client-login', methods=['GET', 'POST'])
def client_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        logger.info(f"Client login attempt - Email: {email}, IP: {request.remote_addr}")
        
        client = client_db.get(email)
        if client and check_password_hash(client['password'], password):
            session['client'] = email
            logger.info(f"✓ Client login successful - Email: {email}")
            return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', 
                '<div class="container"><div class="alert alert-success"><h2>Welcome to Your Portal</h2><p>Login successful! Client portal features would be available here.</p></div></div>'), 
                title='Client Portal')
        else:
            logger.warning(f"✗ Client login failed - Email: {email}, IP: {request.remote_addr}")
            login_form = '''
            <div class="login-container">
                <h2>Client Portal Login</h2>
                <div class="alert alert-danger">Invalid email or password</div>
                <form method="POST">
                    <div class="form-group">
                        <label>Email Address</label>
                        <input type="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="password" required>
                    </div>
                    <button type="submit" class="btn" style="width: 100%;">Login</button>
                </form>
            </div>
            '''
            return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', login_form), title='Client Login')
    
    login_form = '''
    <div class="login-container">
        <h2>Client Portal Login</h2>
        <form method="POST">
            <div class="form-group">
                <label>Email Address</label>
                <input type="email" name="email" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn" style="width: 100%;">Login</button>
        </form>
    </div>
    '''
    return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', login_form), title='Client Login')

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        twofa = request.form.get('twofa')
        
        # CRITICAL: Log all admin login attempts for HIDS monitoring
        logger.warning(f"🔐 ADMIN LOGIN ATTEMPT - Username: {username}, IP: {request.remote_addr}, Timestamp: {datetime.now().isoformat()}")
        
        admin = admin_db.get(username)
        if admin:
            if check_password_hash(admin['password'], password):
                if admin['twofa_code'] == twofa:
                    session['admin_user'] = username
                    logger.info(f"✓ ADMIN LOGIN SUCCESSFUL - User: {username} ({admin['full_name']}), Role: {admin['role']}, IP: {request.remote_addr}")
                    return redirect(url_for('admin_dashboard'))
                else:
                    logger.warning(f"✗ ADMIN LOGIN FAILED - Invalid 2FA - User: {username}, IP: {request.remote_addr}")
                    return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', 
                        ADMIN_LOGIN_TEMPLATE.replace('{% extends "base.html" %}', '').replace('{% block content %}', '').replace('{% endblock %}', '')),
                        title='Admin Login', error='Invalid two-factor authentication code')
            else:
                logger.warning(f"✗ ADMIN LOGIN FAILED - Invalid password - User: {username}, IP: {request.remote_addr}")
                return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', 
                    ADMIN_LOGIN_TEMPLATE.replace('{% extends "base.html" %}', '').replace('{% block content %}', '').replace('{% endblock %}', '')),
                    title='Admin Login', error='Invalid password')
        else:
            logger.warning(f"✗ ADMIN LOGIN FAILED - Unknown username: {username}, IP: {request.remote_addr}")
            return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', 
                ADMIN_LOGIN_TEMPLATE.replace('{% extends "base.html" %}', '').replace('{% block content %}', '').replace('{% endblock %}', '')),
                title='Admin Login', error='Unknown username')
    
    return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', 
        ADMIN_LOGIN_TEMPLATE.replace('{% extends "base.html" %}', '').replace('{% block content %}', '').replace('{% endblock %}', '')),
        title='Admin Login', error=None)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    username = session.get('admin_user')
    admin = admin_db[username]
    
    logger.info(f"Admin dashboard accessed - User: {username}, IP: {request.remote_addr}")
    
    return render_template_string(BASE_TEMPLATE.replace('{% block content %}{% endblock %}', 
        ADMIN_DASHBOARD_TEMPLATE.replace('{% extends "base.html" %}', '').replace('{% block content %}', '').replace('{% endblock %}', '')),
        title='Admin Dashboard', admin=admin)

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    username = session.get('admin_user')
    if username:
        logger.info(f"Admin logout - User: {username}, IP: {request.remote_addr}")
    session.pop('admin_user', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚀 TechNova Company Website - HIDS Monitoring Ready")
    print("="*70)
    print("\n📋 Admin Test Accounts:")
    print("-" * 70)
    for username, admin in admin_db.items():
        clearance_icon = "⭐" if admin['clearance'] == 'high' else "📌"
        print(f"{clearance_icon} {admin['role']:20} | {username:12} | Clearance: {admin['clearance'].upper()}")
    print("\n🔐 All passwords and 2FA codes are shown on the admin login page")
    print("\n📊 Security Logging:")
    print("   - All admin login attempts logged to: technova_auth.log")
    print("   - Failed logins include username, IP, and timestamp")
    print("   - Successful logins tracked with role information")
    print("\n🌐 Server starting at: http://127.0.0.1:5000")
    print("="*70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)

    