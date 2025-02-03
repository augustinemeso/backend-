from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from jwt import encode, decode 
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate 

app = Flask(__name__)

DB_CONFIG = {
    "database": "postgres",
    "user": "postgres.utllxzyxclyzpbttrpgn",
    "password": "T50agGKffDlt190J",
    "host": "aws-0-ap-south-1.pooler.supabase.com",
    "port": 5432
}

# Set up database URI for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)

migrate = Migrate(app, db)
CORS(app)  # Enable CORS for frontend-backend communication

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret key for JWT
app.config['SECRET_KEY'] = 'your-secret-key'

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Todo model
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create database tables
with app.app_context():
    db.create_all()

# Route for the home page
@app.route('/')
def home():
    return jsonify({'message': 'Welcome to the To-Do List API!'})

# Route for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    # Hash the password before storing it with pbkdf2:sha256
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        # Create JWT token using timezone-aware datetime
        token = encode({
            'user_id': user.id,
            'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=30)
        }, str(app.config['SECRET_KEY']), algorithm='HS256')
        
        # Convert bytes to string if needed
        if isinstance(token, bytes):
            token = token.decode('utf-8')
            
        return jsonify({'token': token})

    return jsonify({'message': 'Invalid credentials'}), 401
# Helper function to verify token
def verify_token():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])  # Fetch user using user_id

        if not user:
            return jsonify({'message': 'User not found'}), 404

        return user
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

# Protected route to get todos
@app.route('/todos', methods=['GET'])
def get_todos():
    user = verify_token()
    if isinstance(user, tuple):  # In case of error
        return user

    todos = Todo.query.filter_by(user_id=user.id).all()
    return jsonify({'todos': [{'id': todo.id, 'text': todo.text} for todo in todos]})

# Protected route to add a todo
@app.route('/todos', methods=['POST'])
def add_todo():
    user = verify_token()
    if isinstance(user, tuple):  # In case of error
        return user

    todo_data = request.get_json()
    if not todo_data or not todo_data.get('text'):
        return jsonify({'message': 'Todo text is required'}), 400

    new_todo = Todo(text=todo_data['text'], user_id=user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message': 'Todo added successfully'})

if __name__ == '__main__':
    app.run(debug=True)
