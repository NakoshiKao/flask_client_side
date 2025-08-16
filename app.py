import os

import jwt
from flask import Flask, render_template, request, url_for, redirect, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_jwt_extended import (create_access_token, current_user, jwt_required,
                                JWTManager, get_jwt_identity, set_access_cookies, get_jwt)
from datetime import datetime, timedelta, timezone
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from jinja2.compiler import generate


app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'secret'  #need to change later
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER']='live.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'api'
app.config['MAIL_PASSWORD'] = '<YOUR_API_TOKEN>'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False


mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
s = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def generate_password_hash(self, password):
        self.password = password
        return password

def generate_verification_token(email):
    return s.dumps(email, salt='email_confirm')


def confirm_verification_token(token):
    try:
        email = s.loads(token, salt='email_confirm', max_age=86400)
        return email
    except SignatureExpired:
        return False
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Forms()
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            return jsonify('Invalid data'), 400

        if User.query.filter_by(username=username).first():
            return jsonify('User already exists'), 400

        if User.query.filter_by(email=email).first():
            return jsonify('User already exists'), 400

        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        token = generate_verification_token(user.email)
        confirm_url = url_for('verify_email', token=token, _external=True)
        html = render_template('verify_email.html', confirm_url=confirm_url)
        subject = 'Please confirm your email'
        msg = Message(subject=subject,
                      sender='test@gmail.com',
                      recipients=[email],
                      body=f"Name:{username}\nEmail:{email}",
                      html=html
                      )
        mail.send(msg)
        flash('A verification email has been sent.', 'success')
        return jsonify('User created'), 201


@app.route('/verify/<token>')
def verify_email(token):
    email = confirm_verification_token()
    if not email:
        flash('The verification link is invalid or has expired')
        return redirect(url_for('register'))



# @jwt.user_identity_loader
# def user_lookup(user):
#     return user.id
#
#
# @jwt.user_lookup_loader
# def user_lookup_callback(jwt_header, jwt_data):
#     identity = jwt_data['sub']
#     return User.query.filter_by(id=identity).one_or_none()

@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()['exp']
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity(), expires_delta=True)
            set_access_cookies(response, access_token)
        return response

    except (RuntimeError, KeyError):
        return response

def resend_verification_email():
    if current_user.is_confirmed:
        flash('Your account has already been confirmed.', )
        return redirect(url_for('home'))
    token = generate_verification_token(current_user.email)
    confirm_url = url_for('verify_email', token=token, _external=True)
    html = render_template('verify_email.html', confirm_url=confirm_url)
    subject = 'Please confirm your email'
    msg = Message(subject=subject,
                  sender='test@gmail.com',
                  recipients=[current_user.email],
                  body=f"Name:{current_user.username}\nEmail:{current_user.email}",
                  html=html
                  )
    mail.send(msg)
    flash('A verification email has been sent.', 'success')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).one_or_none()
    if not user or user['password'] != password:
        return jsonify({'message': 'Username or password is invalid!'}), 401

    response = jsonify({'message': 'Logged in successfully!'})
    access_token = create_access_token(identity=username, expires_delta=True)
    set_access_cookies(response, access_token)
    return jsonify(response)


@app.route('/login_opt_protected', methods=['GET'])
@jwt_required(optional=True)
def protected():
    current_identity = get_jwt_identity()
    if current_identity:
        return jsonify(logged_in_as=current_identity), 200
    else:
        return jsonify(logged_id_as='guest'), 401


@app.route('/logout', methods=['POST'])
def logout():
    if request.method == 'POST':
        pass


def send_password_reset_email(user):
    token = user.get_reset_password_token()
    msg = Message(
                  sender='test@gmail.com',
                  recipients=[current_user.email],
                  body=f"Name:{current_user.username}\nEmail:{current_user.email}",
                  html=render_template('reset_password.html', user=user, token=token))
    mail.send(msg)

@app.route('/reset_password', methods=['POST'])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(email=form.email.data).one_or_none()
        if not user:
            return jsonify({'message': 'Email not found!'}), 401
        if user:
            send_password_reset_email(user)
        flash('Check your email to reset your password' )
        return redirect(url_for('login'))
    return render_template('reset_password.html', title='Reset Password', form=form)


if __name__ == '__main__':
    app.run()
