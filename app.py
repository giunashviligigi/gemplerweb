from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import re

app = Flask(__name__)
app.secret_key = 'idk_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///services.db'
app.config['SQLALCHEMY_BINDS'] = {'users': 'sqlite:///users.db'}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    surname = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    service = db.Column(db.String(100))

    def __init__(self, name, surname, phone, service):
        self.name = name
        self.surname = surname
        self.phone = phone
        self.service = service


class User(UserMixin, db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    role = db.Column(db.String(20))

    def __init__(self, username, password, phone, role):
        self.username = username
        self.password = password
        self.phone = phone
        self.role = role

    def is_active(self):
        return True


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class MyApp:
    def __init__(self):
        self.app = app
        self.db = db
        self.login_manager = login_manager
        self.routes()
        self.create_all()
        self.login_manager_setup()

    def routes(self):
        self.app.add_url_rule('/', 'home', self.home)
        self.app.add_url_rule('/home', 'home', self.home)
        self.app.add_url_rule('/services', 'service', self.service)
        self.app.add_url_rule('/order/<service_name>', 'order_confirmation', self.order_confirmation)
        self.app.add_url_rule('/submit_order', 'submit_order', self.submit_order, methods=['POST'])
        self.app.add_url_rule('/admin', 'admin_login', self.admin_login, methods=['GET', 'POST'])
        self.app.add_url_rule('/admin/dashboard', 'admin_dashboard', self.admin_dashboard)
        self.app.add_url_rule('/admin/logout', 'admin_logout', self.admin_logout)
        self.app.add_url_rule('/contact', 'contact', self.contact)
        self.app.add_url_rule('/register', 'register', self.register, methods=['GET', 'POST'])
        self.app.add_url_rule('/login', 'login', self.login, methods=['GET', 'POST'])
        self.app.add_url_rule('/logout', 'logout', self.logout)
        self.app.add_url_rule('/my_account', 'my_account', self.my_account, methods=['GET', 'POST'])
        self.app.add_url_rule('/employee_dashboard', 'employee_dashboard', self.employee_dashboard)
        
    def create_all(self):
        with self.app.app_context():
            self.db.create_all()

            # Check if the admin account already exists
            admin_user = User.query.filter_by(username='gempler2023').first()
            if not admin_user:
                # Create a new admin user
                hashed_password = generate_password_hash('hardtofind')
                admin_user = User(username='gempler2023', password=hashed_password, phone='', role='admin')
                self.db.session.add(admin_user)
                self.db.session.commit()

    def login_manager_setup(self):
        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))

        @login_manager.unauthorized_handler
        def unauthorized():
            if request.endpoint == 'admin_dashboard':
                # Redirect to the admin login page if accessing the admin dashboard without authorization
                return redirect(url_for('admin_login'))
            else:
                # Redirect to the default login page for other unauthorized routes
                return redirect(url_for('login'))

        login_manager.login_view = 'login'
        login_manager.login_message_category = 'info'

    def home(self):
        return render_template('home.html')

    def service(self):
        return render_template('services.html')

    def contact(self):
        return render_template('contact.html')

    def order_confirmation(self, service_name):
        return render_template('order.html', service=service_name)

    @login_required
    def submit_order(self):
        name = request.form['name']
        surname = request.form['surname']
        phone = request.form['phone']
        service = request.form['service']

        new_service = Service(name=name, surname=surname, phone=phone, service=service)
        with self.app.app_context():
            self.db.session.add(new_service)
            self.db.session.commit()

        response = {'service': service}

        return jsonify(response)

    def admin_login(self):
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            # LogIn logic
            admin_user = User.query.filter_by(username=username, role='admin').first()
            if admin_user and check_password_hash(admin_user.password, password):
                # Log in the user
                login_user(admin_user)

                # Redirect to the admin dashboard
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Incorrect username or password', 'error')
                return render_template('admin.html')

        return render_template('admin.html')

    @login_required
    def admin_dashboard(self):
        if current_user.is_authenticated and current_user.role == 'admin':
            with self.app.app_context():
                orders = Service.query.all()
                users = User.query.all()
            return render_template('list.html', orders=orders, users=users)
        else:
            return redirect(url_for('admin_login'))

    def admin_logout(self):
        session.pop('admin_logged_in', None)
        return redirect(url_for('home'))

    def register(self):
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            phone = request.form['phone']
            role = request.form['role']

            # Validate passwords
            if len(password) < 8 or not any(char.isupper() for char in password) or not any(char.isdigit() for char in password):
                flash('Password must be at least 8 characters long and contain at least one uppercase letter and one digit', 'error')
                return redirect(url_for('register'))

            # Check if passwords match
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return redirect(url_for('register'))

            # Check if username already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists', 'error')
                return redirect(url_for('register'))

            # Create a new user
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password, phone=phone, role=role)
            with self.app.app_context():
                self.db.session.add(new_user)
                self.db.session.commit()

            return redirect(url_for('home'))

        return render_template('register.html')

    def login(self):
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            # Check if the username exists
            user = User.query.filter_by(username=username).first()
            if not user:
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))

            # Check if the password is correct
            if not check_password_hash(user.password, password):
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))

            # User authenticated successfully, log in the user
            login_user(user)

            # Redirect based on the user's role
            if user.role == 'customer':
                return redirect(url_for('service'))
            elif user.role == 'employee':
                return redirect(url_for('employee_dashboard'))
            else:
                # Handle other roles as needed
                flash('Invalid user role', 'error')
                return redirect(url_for('login'))

        return render_template('login.html')

    @login_required
    def logout(self):
        logout_user()
        return redirect(url_for('home'))
    
    @login_required
    def my_account(self):
        if request.method == 'POST':
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            # Check if the current password is correct
            if not check_password_hash(current_user.password, current_password):
                flash('Incorrect current password', 'error')
                return redirect(url_for('my_account'))

            # Check if the new password and confirm password match
            if new_password != confirm_password:
                flash('New password and confirm password do not match', 'error')
                return redirect(url_for('my_account'))

            # Check password requirements
            if len(new_password) < 8 or not re.search(r'\d', new_password) or not re.search(r'[A-Z]', new_password):
                flash('Password must be at least 8 characters long and contain at least one uppercase letter and one digit', 'error')
                return redirect(url_for('my_account'))

            # Update the password
            current_user.password = generate_password_hash(new_password)
            self.db.session.commit()

            flash('Password updated successfully', 'success')
            return redirect(url_for('my_account'))

        return render_template('my_account.html')

    @login_required
    def employee_dashboard(self):
        if current_user.is_authenticated and current_user.role == 'employee':
            with self.app.app_context():
                orders = Service.query.all()
            return render_template('employee_dashboard.html', orders=orders)
        else:
            return redirect(url_for('login'))



if __name__ == '__main__':
    my_app = MyApp()
    my_app.app.run(debug=False)
