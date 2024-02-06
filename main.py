from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import json
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import environment as env
from bs4 import BeautifulSoup

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your-secret-key'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)  # Changed from username to email
    password_hash = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Sign Up API
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data['email']
    password = data['password']
    if User.query.filter_by(email=email).first():  # Changed from username to email
        return jsonify({'message': 'User already exists'}), 400
    new_user = User(email=email)  # Changed from username to email
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201


# Log In API
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()  # Changed from username to email
    if user and user.check_password(data['password']):
        login_user(user)
        return jsonify({'message': 'Logged in successfully'}), 200
    return jsonify({'message': 'Invalid email or password'}), 401  # Adjusted message


# Log Out API
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200


# Price API route
@app.route('/price/<item_name>')
def get_price(item_name):
    price_item = {}
    try:
        # Send a GET request to the URL
        response = requests.get(f"{env.ALDI_URL}={item_name}")
        # Parse the HTML content of the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find the 'searchResults' div
        search_results_div = soup.find(id='searchResults')

        # Extract the 'data-context' attribute, which is a JSON string
        data_context_json = search_results_div['data-context']

        # Parse the JSON string into a Python dictionary
        data_context = json.loads(data_context_json)

        # Extract the first four items from the SearchResults list
        first_four_items = data_context['SearchResults'][:4]

        # Iterate through the first four items and print their details
        for item in first_four_items:
            name = item['FullDisplayName']
            quantity = item['SizeVolume']
            price = item['ListPrice']
            print(f"Name: {name}, Quantity: {quantity}, Price: £{price}")
        return jsonify(), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host=env.SERVER, port=6060, debug=True)
