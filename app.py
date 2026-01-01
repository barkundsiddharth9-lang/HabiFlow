from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100))  # New Column Added
    password = db.Column(db.String(100), nullable=False)
    
    # Security Questions
    security_q1 = db.Column(db.String(200))
    security_a1 = db.Column(db.String(200))
    security_q2 = db.Column(db.String(200))
    security_a2 = db.Column(db.String(200))
    
    # User Data (Storing JSON blob for habits)
    habit_data = db.Column(db.Text, default="{}")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'success': False, 'message': 'Username already exists'})

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    new_user = User(
        first_name=data['first_name'],
        last_name=data['last_name'],
        username=data['username'],
        password=hashed_password,
        security_q1=data['q1'],
        security_a1=data['a1'].lower().strip(),
        security_q2=data['q2'],
        security_a2=data['a2'].lower().strip(),
        email=data.get('email', '') 
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Account created! Please login.'})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    
    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        full_name = f"{user.first_name} {user.last_name}".strip()
        return jsonify({
            'success': True, 
            'username': user.username, 
            'first_name': full_name,
            'email': user.email if user.email else ""
        })
    
    return jsonify({'success': False, 'message': 'Invalid username or password'})

# --- NEW: CHECK SESSION ROUTE ---
@app.route('/api/check_session', methods=['GET'])
def check_session():
    if current_user.is_authenticated:
        # User is already logged in
        full_name = f"{current_user.first_name} {current_user.last_name}".strip()
        return jsonify({
            'is_logged_in': True, 
            'username': current_user.username, 
            'first_name': full_name,
            'email': current_user.email if current_user.email else ""
        })
    return jsonify({'is_logged_in': False})

@app.route('/api/get_security_questions', methods=['POST'])
def get_security_questions():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user:
        return jsonify({
            'success': True, 
            'q1': user.security_q1,
            'q2': user.security_q2
        })
    return jsonify({'success': False, 'message': 'User not found'})

@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    
    if user:
        if (user.security_a1 == data['a1'].lower().strip() and 
            user.security_a2 == data['a2'].lower().strip()):
            
            user.password = generate_password_hash(data['new_password'], method='pbkdf2:sha256')
            db.session.commit()
            return jsonify({'success': True, 'message': 'Password reset successful!'})
        
    return jsonify({'success': False, 'message': 'Incorrect security answers.'})

# --- SETTINGS ROUTES ---

@app.route('/api/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not check_password_hash(current_user.password, current_password):
        return jsonify({'success': False, 'message': 'Current password is incorrect'})

    current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
    db.session.commit()
    return jsonify({'success': True, 'message': 'Password changed successfully!'})

@app.route('/api/update_security_questions', methods=['POST'])
@login_required
def update_security_questions():
    data = request.json
    password = data.get('password')

    if not check_password_hash(current_user.password, password):
        return jsonify({'success': False, 'message': 'Incorrect password. Cannot update questions.'})

    current_user.security_q1 = data['q1']
    current_user.security_a1 = data['a1'].lower().strip()
    current_user.security_q2 = data['q2']
    current_user.security_a2 = data['a2'].lower().strip()
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'Security questions updated successfully!'})

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.json
    full_name = data.get('full_name', '')
    email = data.get('email', '')

    name_parts = full_name.strip().split(' ', 1)
    current_user.first_name = name_parts[0]
    if len(name_parts) > 1:
        current_user.last_name = name_parts[1]
    else:
        current_user.last_name = ''

    current_user.email = email
    db.session.commit()
    return jsonify({'success': True, 'message': 'Profile updated successfully!'})

# --- DATA ROUTES ---

@app.route('/api/save_data', methods=['POST'])
@login_required
def save_data():
    data = request.json
    current_user.habit_data = json.dumps(data)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/get_data', methods=['GET'])
@login_required
def get_data():
    if not current_user.habit_data:
        return jsonify({})
    return jsonify(json.loads(current_user.habit_data))

@app.route('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'success': True})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)