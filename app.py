from flask import Flask, render_template, redirect, url_for, request, flash

app = Flask(__name__)
app.secret_key = 'jtech_secret'  # needed for flashing messages

# Mock user data (for login)
USERS = {"admin": "1234"}

# Mock parts
PARTS = [
    {"id": 1, "name": "Intel Core i5-12400F", "price": 150, "category": "CPU"},
    {"id": 2, "name": "AMD Ryzen 5 5600", "price": 160, "category": "CPU"},
    {"id": 3, "name": "NVIDIA RTX 4070", "price": 500, "category": "GPU"},
    {"id": 4, "name": "Corsair Vengeance 16GB", "price": 70, "category": "RAM"},
]

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/parts')
def parts():
    return render_template('parts.html', parts=PARTS)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        password = request.form['password']
        if user in USERS and USERS[user] == password:
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials, try again.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form['username']
        password = request.form['password']
        if user in USERS:
            flash('Username already exists.', 'danger')
        else:
            USERS[user] = password
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
