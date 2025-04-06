import os
from flask import Flask, render_template, request, redirect, url_for, flash
from auth_utils import generate_signature, verify_signature

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Store user credentials
user_data = {}

@app.route('/')
def landing():
    
    """Landing page with options to sign up or sign in."""
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Register new user
        if username in user_data:
            flash("User already exists. Please sign in instead.")
        else:
            # Unpack all 5 values returned by generate_signature
            public_key, signature, salt, quantum_hash, shared_key = generate_signature(password)
            if public_key is None:  # Check if signature generation failed
                flash("Failed to generate signature. Please try again.")
                return render_template('signup.html')
            user_data[username] = {
                'public_key': public_key,
                'signature': signature,
                'salt': salt,  # Store the salt
                'quantum_hash': quantum_hash,  # Store quantum hash
                'shared_key': shared_key  # Store the shared key
            }
            flash("User registered successfully! Please sign in.")
            return redirect(url_for('signin'))

    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists and verify credentials
        if username in user_data:
            signature = user_data[username]['signature']
            salt = user_data[username]['salt']
            quantum_hash = user_data[username]['quantum_hash']
            shared_key = user_data[username]['shared_key']  # Retrieve shared_key
            if verify_signature(signature, password, salt, quantum_hash, shared_key):
                flash("Sign in successful!")
                return redirect(url_for('home'))
            else:
                flash("Invalid credentials. Please try again.")
        else:
            flash("User not found. Please sign up.")

    return render_template('signin.html')

@app.route('/home')
def home():
    return render_template('home.html')

if __name__ == "__main__":
    app.run(debug=True)