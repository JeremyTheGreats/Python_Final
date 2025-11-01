from flask import Flask, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'jtech_secret'  

DB_NAME = "jtech.db"

def init_db():
    if not os.path.exists(DB_NAME):
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute('''CREATE TABLE users (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                username TEXT UNIQUE NOT NULL,
                                email TEXT NOT NULL,
                                password TEXT NOT NULL
                            );''')
            print("✅ Database and users table created successfully!")

init_db()

@app.route('/')
def home():
    return render_template('home.html')



@app.route('/parts')
def parts():
    if 'user' not in session:
        flash('You must log in first to view parts.', 'danger')
        return redirect(url_for('login'))
    return render_template('parts.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT username, password FROM users WHERE username = ?", (username,))
            user = cur.fetchone()

        if user and check_password_hash(user[1], password):
            session['user'] = user[0]
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')
        

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # ✅ Password confirmation check
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        # ✅ Hash the password for security
        hashed_password = generate_password_hash(password)

        try:
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_password)
                )
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Username or email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/choose-purpose', methods=['GET', 'POST'])
def choose_purpose():
    if request.method == 'POST':
        purpose = request.form['purpose']
        session['purpose'] = purpose
        return redirect(url_for('choose_cpu'))
    
    return render_template('choose_purpose.html')


@app.route('/choose-cpu', methods=['GET', 'POST'])
def choose_cpu():
    if 'user' not in session:
        flash('Please log in to build your PC.', 'warning')
        return redirect(url_for('login'))
    
    purpose = session.get('purpose', None)
    if not purpose:
        return redirect(url_for('choose_purpose'))

    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name, price, description FROM parts WHERE category='CPU' AND tier=?", (purpose,))
        cpus = cur.fetchall()

    if request.method == 'POST':
        selected_cpu = request.form['cpu']
        session['cpu'] = selected_cpu
        return redirect(url_for('choose_mobo'))  # ✅ Go to next step

    return render_template('choose_cpu.html', purpose=purpose, cpus=cpus)


@app.route('/choose-mobo', methods=['GET', 'POST'])
def choose_mobo():
    purpose = session.get('purpose', None)
    if not purpose:
        return redirect(url_for('choose_purpose'))

    if request.method == 'POST':
        selected_mobo = request.form['mobo']
        session['mobo'] = selected_mobo
        return redirect(url_for('choose_ram'))  # Next step after mobo

    return render_template('choose_mobo.html', purpose=purpose)


@app.route('/choose-ram', methods=['GET', 'POST'])
def choose_ram():
    purpose = session.get('purpose', None)
    if not purpose:
        return redirect(url_for('choose_purpose'))

    if request.method == 'POST':
        selected_ram = request.form['ram']
        session['ram'] = selected_ram
        flash('RAM selected successfully!', 'success')
        return redirect(url_for('choose_gpu'))  # ✅ next step later

    return render_template('choose_ram.html', purpose=purpose)


@app.route('/choose-gpu', methods=['GET', 'POST'])
def choose_gpu():
    if 'user' not in session:
        flash('Please log in to build your PC.', 'warning')
        return redirect(url_for('login'))

    purpose = session.get('purpose', None)
    if not purpose:
        return redirect(url_for('choose_purpose'))

    if request.method == 'POST':
        session['gpu'] = request.form['gpu']
        return redirect(url_for('choose_storage'))  # ✅ next step: storage

    return render_template('choose_gpu.html', purpose=purpose)


@app.route('/choose-storage', methods=['GET', 'POST'])
def choose_storage():
    if 'user' not in session:
        flash('Please log in to build your PC.', 'warning')
        return redirect(url_for('login'))
    
    purpose = session.get('purpose', None)
    if not purpose:
        return redirect(url_for('choose_purpose'))

    if request.method == 'POST':
        selected_storage = request.form['storage']
        session['storage'] = selected_storage
        return redirect(url_for('choose_psu'))  # next step later

    return render_template('choose_storage.html', purpose=purpose)


@app.route('/choose-psu', methods=['GET', 'POST'])
def choose_psu():
    if 'user' not in session:
        flash('Please log in to build your PC.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        session['psu'] = request.form['psu']
        return redirect(url_for('choose_case'))  # next step

    return render_template('choose_psu.html')


@app.route('/choose-case', methods=['GET', 'POST'])
def choose_case():
    if 'user' not in session:
        flash('Please log in to build your PC.', 'warning')
        return redirect(url_for('login'))

    purpose = session.get('purpose', None)
    if not purpose:
        return redirect(url_for('choose_purpose'))

    if request.method == 'POST':
        session['case'] = request.form['case']
        return redirect(url_for('summary'))  # next step (summary page) later

    return render_template('choose_case.html', purpose=purpose)


@app.route('/summary')
def summary():
    if 'user' not in session:
        flash('Please log in to view your build summary.', 'warning')
        return redirect(url_for('login'))

    # Gather all selected parts
    selected_parts = {
        'Purpose': session.get('purpose', 'Not selected'),
        'CPU': session.get('cpu', 'Not selected'),
        'Motherboard': session.get('mobo', 'Not selected'),
        'RAM': session.get('ram', 'Not selected'),
        'GPU': session.get('gpu', 'Not selected'),
        'Storage': session.get('storage', 'Not selected'),
        'PSU': session.get('psu', 'Not selected'),
        'Case': session.get('case', 'Not selected')
    }

    return render_template('summary.html', parts=selected_parts)


@app.route('/save-build', methods=['POST'])
def save_build():
    if 'user' not in session:
        flash('Please log in to save your build.', 'warning')
        return redirect(url_for('login'))

    username = session['user']
    purpose = session.get('purpose', '')
    cpu = session.get('cpu', '')
    mobo = session.get('mobo', '')
    ram = session.get('ram', '')
    gpu = session.get('gpu', '')
    storage = session.get('storage', '')
    psu = session.get('psu', '')
    pc_case = session.get('case', '')

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('''INSERT INTO builds 
                        (username, purpose, cpu, motherboard, ram, gpu, storage, psu, pc_case)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (username, purpose, cpu, mobo, ram, gpu, storage, psu, pc_case))

    flash('✅ Your PC build has been saved successfully!', 'success')
    return redirect(url_for('home'))


@app.route('/my-builds')
def my_builds():
    if 'user' not in session:
        flash('Please log in to view your builds.', 'warning')
        return redirect(url_for('login'))

    username = session['user']

    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, purpose, cpu, motherboard, ram, gpu, storage, psu, pc_case, date_created FROM builds WHERE username=? ORDER BY date_created DESC', (username,))
        builds = cur.fetchall()

    return render_template('my_builds.html', builds=builds)


if __name__ == '__main__':
    app.run(debug=True)
