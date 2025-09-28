"""
Bug Tracking Collaboration Website
A full-stack Flask application for collaborative bug tracking with group management
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'txt', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('bug_tracker.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Groups table
    c.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            leader_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (leader_id) REFERENCES users (id)
        )
    ''')
    
    # Group memberships table
    c.execute('''
        CREATE TABLE IF NOT EXISTS memberships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (group_id) REFERENCES groups (id),
            UNIQUE(user_id, group_id)
        )
    ''')
    
    # Bugs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS bugs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            reporter_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            file_path TEXT,
            file_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            approved_at TIMESTAMP,
            FOREIGN KEY (reporter_id) REFERENCES users (id),
            FOREIGN KEY (group_id) REFERENCES groups (id)
        )
    ''')
    
    # Suggestions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS suggestions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users (id),
            FOREIGN KEY (group_id) REFERENCES groups (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect('bug_tracker.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return render_template('signup.html')
        
        conn = get_db_connection()
        
        # Check if user already exists
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (username, email)
        ).fetchone()
        
        if existing_user:
            flash('Username or email already exists!', 'error')
            conn.close()
            return render_template('signup.html')
        
        # Create new user
        password_hash = generate_password_hash(password)
        conn.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, password_hash)
        )
        conn.commit()
        conn.close()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get user's groups
    groups = conn.execute('''
        SELECT g.*, u.username as leader_name,
               CASE WHEN g.leader_id = ? THEN 1 ELSE 0 END as is_leader
        FROM groups g
        JOIN memberships m ON g.id = m.group_id
        JOIN users u ON g.leader_id = u.id
        WHERE m.user_id = ?
        ORDER BY g.name
    ''', (session['user_id'], session['user_id'])).fetchall()
    
    conn.close()
    return render_template('dashboard.html', groups=groups)

@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    """Create a new group"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name'].strip()
        description = request.form['description'].strip()
        
        if not name:
            flash('Group name is required!', 'error')
            return render_template('create_group.html')
        
        conn = get_db_connection()
        
        # Create group
        cursor = conn.execute(
            'INSERT INTO groups (name, description, leader_id) VALUES (?, ?, ?)',
            (name, description, session['user_id'])
        )
        group_id = cursor.lastrowid
        
        # Add creator as member
        conn.execute(
            'INSERT INTO memberships (user_id, group_id) VALUES (?, ?)',
            (session['user_id'], group_id)
        )
        
        conn.commit()
        conn.close()
        
        flash('Group created successfully!', 'success')
        return redirect(url_for('group_detail', group_id=group_id))
    
    return render_template('create_group.html')

@app.route('/group/<int:group_id>')
def group_detail(group_id):
    """Group detail page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Check if user is member of this group
    membership = conn.execute(
        'SELECT * FROM memberships WHERE user_id = ? AND group_id = ?',
        (session['user_id'], group_id)
    ).fetchone()
    
    if not membership:
        flash('You are not a member of this group!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Get group info
    group = conn.execute(
        'SELECT g.*, u.username as leader_name FROM groups g JOIN users u ON g.leader_id = u.id WHERE g.id = ?',
        (group_id,)
    ).fetchone()
    
    # Get group members
    members = conn.execute('''
        SELECT u.username, m.joined_at,
               CASE WHEN g.leader_id = u.id THEN 1 ELSE 0 END as is_leader
        FROM memberships m
        JOIN users u ON m.user_id = u.id
        JOIN groups g ON m.group_id = g.id
        WHERE m.group_id = ?
        ORDER BY is_leader DESC, u.username
    ''', (group_id,)).fetchall()
    
    # Get bugs
    bugs = conn.execute('''
        SELECT b.*, u.username as reporter_name
        FROM bugs b
        JOIN users u ON b.reporter_id = u.id
        WHERE b.group_id = ?
        ORDER BY b.created_at DESC
    ''', (group_id,)).fetchall()
    
    # Get suggestions
    suggestions = conn.execute('''
        SELECT s.*, u.username as author_name
        FROM suggestions s
        JOIN users u ON s.author_id = u.id
        WHERE s.group_id = ?
        ORDER BY s.created_at DESC
    ''', (group_id,)).fetchall()
    
    is_leader = group['leader_id'] == session['user_id']
    
    conn.close()
    return render_template('group_detail.html', 
                         group=group, members=members, bugs=bugs, 
                         suggestions=suggestions, is_leader=is_leader)

@app.route('/invite_user/<int:group_id>', methods=['POST'])
def invite_user(group_id):
    """Invite user to group"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = request.form['username'].strip()
    
    conn = get_db_connection()
    
    # Check if current user is group leader
    group = conn.execute('SELECT leader_id FROM groups WHERE id = ?', (group_id,)).fetchone()
    if not group or group['leader_id'] != session['user_id']:
        flash('Only group leaders can invite users!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Find user to invite
    user_to_invite = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not user_to_invite:
        flash('User not found!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Check if user is already a member
    existing_membership = conn.execute(
        'SELECT id FROM memberships WHERE user_id = ? AND group_id = ?',
        (user_to_invite['id'], group_id)
    ).fetchone()
    
    if existing_membership:
        flash('User is already a member of this group!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Add user to group
    conn.execute(
        'INSERT INTO memberships (user_id, group_id) VALUES (?, ?)',
        (user_to_invite['id'], group_id)
    )
    conn.commit()
    conn.close()
    
    flash(f'User {username} invited successfully!', 'success')
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/upload_bug/<int:group_id>', methods=['POST'])
def upload_bug(group_id):
    """Upload a bug report"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    title = request.form['title'].strip()
    description = request.form['description'].strip()
    
    if not title or not description:
        flash('Title and description are required!', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    
    conn = get_db_connection()
    
    # Check if user is member of this group
    membership = conn.execute(
        'SELECT * FROM memberships WHERE user_id = ? AND group_id = ?',
        (session['user_id'], group_id)
    ).fetchone()
    
    if not membership:
        flash('You are not a member of this group!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    file_path = None
    file_name = None
    
    # Handle file upload
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to avoid conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            file_name = file.filename
            file_path = f'uploads/{filename}'  # Relative path for database
    
    # Insert bug report
    conn.execute('''
        INSERT INTO bugs (title, description, reporter_id, group_id, file_path, file_name)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (title, description, session['user_id'], group_id, file_path, file_name))
    
    conn.commit()
    conn.close()
    
    flash('Bug report submitted successfully!', 'success')
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/approve_bug/<int:bug_id>')
def approve_bug(bug_id):
    """Approve a bug (leader only)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get bug and check if current user is group leader
    bug = conn.execute('''
        SELECT b.*, g.leader_id, g.id as group_id
        FROM bugs b
        JOIN groups g ON b.group_id = g.id
        WHERE b.id = ?
    ''', (bug_id,)).fetchone()
    
    if not bug:
        flash('Bug not found!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    if bug['leader_id'] != session['user_id']:
        flash('Only group leaders can approve bugs!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=bug['group_id']))
    
    # Update bug status
    conn.execute(
        'UPDATE bugs SET status = ?, approved_at = CURRENT_TIMESTAMP WHERE id = ?',
        ('approved', bug_id)
    )
    conn.commit()
    conn.close()
    
    flash('Bug approved successfully!', 'success')
    return redirect(url_for('group_detail', group_id=bug['group_id']))

@app.route('/submit_suggestion/<int:group_id>', methods=['POST'])
def submit_suggestion(group_id):
    """Submit a suggestion"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    title = request.form['title'].strip()
    description = request.form['description'].strip()
    
    if not title or not description:
        flash('Title and description are required!', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    
    conn = get_db_connection()
    
    # Check if user is member of this group
    membership = conn.execute(
        'SELECT * FROM memberships WHERE user_id = ? AND group_id = ?',
        (session['user_id'], group_id)
    ).fetchone()
    
    if not membership:
        flash('You are not a member of this group!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Insert suggestion
    conn.execute('''
        INSERT INTO suggestions (title, description, author_id, group_id)
        VALUES (?, ?, ?, ?)
    ''', (title, description, session['user_id'], group_id))
    
    conn.commit()
    conn.close()
    
    flash('Suggestion submitted successfully!', 'success')
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/approve_suggestion/<int:suggestion_id>')
def approve_suggestion(suggestion_id):
    """Approve a suggestion (leader only)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get suggestion and check if current user is group leader
    suggestion = conn.execute('''
        SELECT s.*, g.leader_id, g.id as group_id
        FROM suggestions s
        JOIN groups g ON s.group_id = g.id
        WHERE s.id = ?
    ''', (suggestion_id,)).fetchone()
    
    if not suggestion:
        flash('Suggestion not found!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    if suggestion['leader_id'] != session['user_id']:
        flash('Only group leaders can approve suggestions!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=suggestion['group_id']))
    
    # Update suggestion status
    conn.execute(
        'UPDATE suggestions SET status = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ?',
        ('approved', suggestion_id)
    )
    conn.commit()
    conn.close()
    
    flash('Suggestion approved successfully!', 'success')
    return redirect(url_for('group_detail', group_id=suggestion['group_id']))

@app.route('/reject_suggestion/<int:suggestion_id>')
def reject_suggestion(suggestion_id):
    """Reject a suggestion (leader only)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get suggestion and check if current user is group leader
    suggestion = conn.execute('''
        SELECT s.*, g.leader_id, g.id as group_id
        FROM suggestions s
        JOIN groups g ON s.group_id = g.id
        WHERE s.id = ?
    ''', (suggestion_id,)).fetchone()
    
    if not suggestion:
        flash('Suggestion not found!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    if suggestion['leader_id'] != session['user_id']:
        flash('Only group leaders can reject suggestions!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=suggestion['group_id']))
    
    # Update suggestion status
    conn.execute(
        'UPDATE suggestions SET status = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ?',
        ('rejected', suggestion_id)
    )
    conn.commit()
    conn.close()
    
    flash('Suggestion rejected!', 'success')
    return redirect(url_for('group_detail', group_id=suggestion['group_id']))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)