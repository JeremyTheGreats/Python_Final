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
            cur.execute("SELECT username, password, role FROM users WHERE username = ?", (username,))
            user = cur.fetchone()

        if user and check_password_hash(user[1], password):
            session['user'] = user[0]
            session['role'] = user[2]  

            flash('Login successful!', 'success')
            
           
            if user[2] == 'admin':
                
                return redirect(url_for('admin_dashboard'))

            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')



@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Access denied! Admins only.', 'danger')
        return redirect(url_for('login'))
    
    return render_template('admin_dashboard.html')
        


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

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
        selected_value = request.form['cpu']
        cpu_name, cpu_price = selected_value.split('|')
        
        session['cpu_price'] = float(cpu_price)
        
        return redirect(url_for('choose_mobo'))

    return render_template('choose_cpu.html', purpose=purpose, cpus=cpus)


@app.route('/choose-mobo', methods=['GET', 'POST'])
def choose_mobo():
    purpose = session.get('purpose', None)
    if not purpose:
        return redirect(url_for('choose_purpose'))

    if request.method == 'POST':
        selected_mobo = request.form['mobo']
        mobo_name, mobo_price = selected_mobo.split('|') 
        
        session['mobo_price'] = float(mobo_price)
        
        return redirect(url_for('choose_ram'))  

    return render_template('choose_mobo.html', purpose=purpose)


@app.route('/choose-ram', methods=['GET', 'POST'])
def choose_ram():
    purpose = session.get('purpose', None)
    if not purpose:
        return redirect(url_for('choose_purpose'))

    if request.method == 'POST':
        selected_ram = request.form['ram']
        ram_name, ram_price = selected_ram.split('|') 
        
        session['ram_price'] = float(ram_price)
        
        flash('RAM selected successfully!', 'success')
        return redirect(url_for('choose_gpu'))  

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
        session_gpu = request.form['gpu']
        
        gpu_name, gpu_price = session_gpu.split('|')
        
        session['gpu_price'] = float(gpu_price)
        
        return redirect(url_for('choose_storage'))  

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
        storage_name, storage_price = selected_storage.split('|')
        session['storage_price'] = float(storage_price)
        
        return redirect(url_for('choose_psu')) 

    return render_template('choose_storage.html', purpose=purpose)


@app.route('/choose-psu', methods=['GET', 'POST'])
def choose_psu():
    if 'user' not in session:
        flash('Please log in to build your PC.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        session_psu = request.form['psu']
        psu_name, psu_price = session_psu.split('|')
        
        session['psu_price'] = float(psu_price)
        
        return redirect(url_for('choose_case')) 

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
        session_case = request.form['case']
        case_name, case_price = session_case.split('|')
        
        session['case_price'] = float(case_price)
        
        return redirect(url_for('delivery_info'))

    return render_template('choose_case.html', purpose=purpose)


@app.route('/summary')
def summary():
    if 'user' not in session:
        flash('Please log in to view your build summary.', 'warning')
        return redirect(url_for('login'))

    
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

    user = session['user']

    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute('''
            SELECT id, purpose, cpu, mobo, ram, gpu, storage, psu, cases, fullname, address, contact
            FROM builds
            WHERE user = ?
            ORDER BY id DESC
        ''', (user,))
        builds = cur.fetchall()

    return render_template('my_builds.html', builds=builds)


@app.route('/view-build/<int:id>')
def view_build(id):
    if 'user' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    user = session['user']

    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute('''
            SELECT id, purpose, cpu, mobo, ram, gpu, storage, psu, cases, fullname, address, contact, status, price
            FROM builds
            WHERE id = ? AND user = ?
        ''', (id, user))
        build = cur.fetchone()

    if not build:
        flash('Build not found or access denied.', 'danger')
        return redirect(url_for('my_builds'))

    return render_template('view_build.html', build=build)



@app.route('/delivery-info', methods=['GET', 'POST'])
def delivery_info():
    if 'user' not in session:
        flash('Please log in to continue.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        fullname = request.form['fullname']
        address = request.form['address']
        contact = request.form['contact']

       
        purpose = session.get('purpose')
        cpu = session.get('cpu')
        mobo = session.get('mobo')
        ram = session.get('ram')
        gpu = session.get('gpu')
        storage = session.get('storage')
        psu = session.get('psu')
        case = session.get('case')

        user = session['user']
        cpu_price = session.get('cpu_price', 0)
        mobo_price = session.get('mobo_price', 0)
        ram_price = session.get('ram_price', 0)
        gpu_price = session.get('gpu_price', 0)
        storage_price = session.get('storage_price', 0)
        psu_price = session.get('psu_price', 0)
        case_price = session.get('case_price', 0)
        
        total_price = cpu_price + mobo_price + ram_price + gpu_price + storage_price + psu_price + case_price
                       
        
        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO builds (user, purpose, cpu, mobo, ram, gpu, storage, psu, cases, fullname, address, contact, status, price)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user, purpose, cpu, mobo, ram, gpu, storage, psu, case, fullname, address, contact, "Pending", total_price))
            conn.commit()

        flash('Your build and delivery info have been saved!', 'success')
        return redirect(url_for('my_builds'))

    return render_template('delivery_info.html')


@app.route('/admin/view-orders')
def admin_view_orders():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM builds ORDER BY id DESC")
        builds = cur.fetchall()

    return render_template('admin_view_orders.html', builds=builds)


@app.route('/admin/update-status/<int:build_id>', methods=['POST'])
def admin_update_status(build_id):
    if 'user' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    new_status = request.form['status']

    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE builds SET status = ? WHERE id = ?", (new_status, build_id))
        conn.commit()

    flash('✅ Order status updated successfully!', 'success')
    return redirect(url_for('admin_view_orders'))



@app.route('/admin/mark-delivered/<int:order_id>', methods=['POST'])
def mark_delivered(order_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status = 'Delivered' WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()
    flash('Order marked as delivered!', 'success')
    return redirect(url_for('view_orders'))


@app.route('/admin/manage-users')
def manage_users():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, username, role FROM users ORDER BY id ASC")
        users = cur.fetchall()

    return render_template('admin_manage_users.html', users=users)


@app.route('/admin/update-role/<int:user_id>', methods=['POST'])
def update_role(user_id):
    if 'user' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    new_role = request.form['role']

    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()

    flash('✅ User role updated successfully!', 'success')
    return redirect(url_for('manage_users'))




if __name__ == '__main__':
    app.run(debug=True)
