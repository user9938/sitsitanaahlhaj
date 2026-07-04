import os

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

db = SQLAlchemy()
login_manager = LoginManager()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


def create_app():
    app = Flask(__name__, template_folder=BASE_DIR)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-me')

    default_db_path = os.path.join(BASE_DIR, 'instance', 'users.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', f"sqlite:///{default_db_path}"
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # -- Routes --------------------------------------------------------

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return render_template('index.html', page='home')
        return redirect(url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('index'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')

            if not username or not email or not password:
                flash('Please fill in all fields.', 'danger')
                return redirect(url_for('register'))

            if User.query.filter_by(username=username).first():
                flash('Username already taken.', 'danger')
                return redirect(url_for('register'))

            if User.query.filter_by(email=email).first():
                flash('Email already registered.', 'danger')
                return redirect(url_for('register'))

            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))

        return render_template('index.html', page='register')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                login_user(user)
                flash('Logged in successfully.', 'success')
                return redirect(url_for('index'))

            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

        return render_template('index.html', page='login')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('login'))

    with app.app_context():
        os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)
        db.create_all()

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
