import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, url_for, redirect, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import current_user
from flask_mail import Mail
from flask_wtf import CSRFProtect
from flask_jwt_extended import (create_access_token, current_user, jwt_required,
                                JWTManager, get_jwt_identity, set_access_cookies, get_jwt, unset_jwt_cookies)

from datetime import datetime, timedelta, timezone
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, Serializer
from werkzeug.security import generate_password_hash, check_password_hash

from forms import RegistrationForm, LoginForm, ResetPasswordForm
from service import send_verification_email, send_reset_password_email

load_dotenv()
app = Flask(__name__)
# Проблема: секрети (JWT_SECRET_KEY) захардкоджені прямо у коді. Це небезпечно.
# Ключ має бути у .env файлі і підтягуватися через os.getenv().+
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_COOKIE_SECURE'] = os.getenv('JWT_COOKIE_SECURE')
app.config['JWT_TOKEN_LOCATION'] = os.getenv('JWT_TOKEN_LOCATION')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = os.getenv('JWT_ACCESS_TOKEN_EXPIRES')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')

app.config['MAIL_SERVER']= os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL')


mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
s = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
jwt = JWTManager(app)
csrf = CSRFProtect(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    address = db.Column(db.String(80), unique=True, nullable=True)
    confirmed = db.Column(db.Boolean, default=False)

    # Тут немає поля confirmed (is_confirmed), хоча у коді воно використовується.
    # Це викличе помилки при доступі до current_user.is_confirmed.
    def is_confirmed(self):
        self.confirmed = True
        return self.confirmed

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(os.getenv('SECRET_KEY'))
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = Serializer(os.getenv('SECRET_KEY'))
        try:
            user_id = s.loads(token, max_age=expires_sec)['user_id']
        except Exception:
            return None
        return User.query.get(user_id)

def generate_verification_token(email):
    return s.dumps(email, salt='email_confirm')


def confirm_verification_token(token):
    # Погана практика: функція, яка повинна повертати email, раптово повертає HTTP-відповідь.
    # Це порушує принцип єдиної відповідальності.
    email = s.loads(token, salt='email_confirm', max_age=86400)
    return email



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        address = request.form.get('address')
        # Погана відповідь: краще завжди повертати словник з ключами 'error' або 'message'
        if not username or not email or not password:
            return jsonify({'error':'Invalid data'}), 400
        # Ці перевірки дублюють одна одну і написані не дуже ефективно.
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return jsonify({'error':'User already exists'}), 400


        hash_password = generate_password_hash(password, method='sha256', salt_length=8)
        user = User(username=username, email=email, password=hash_password, address=address)
        db.session.add(user)
        db.session.commit()
        token = generate_verification_token(user.email)
        mail.send(send_verification_email(user, token))
        flash('A verification email has been sent.', 'success')
        return redirect(url_for('verify_email', token=token))


@app.route('/verify/<token>')
def verify_email(token):
    # Критична помилка: confirm_verification_token очікує параметр, але викликається без нього
    # Результат — TypeError.
    email = confirm_verification_token(token)
    if not email:
        flash('The verification link is invalid or has expired')
        return redirect(url_for('register'))
    return redirect(url_for('login'))


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
            # Тут expires_delta=True не працює, воно має бути timedelta.
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response

    except (RuntimeError, KeyError):
        return response

def resend_verification_email():
    # Тут current_user використовується, але інтеграція з Flask-Login відсутня.
    # Це викличе AttributeError.
    if current_user.confirmed == True:
        flash('Your account has already been confirmed.', )
        return redirect(url_for('home'))
    token = generate_verification_token(current_user.email)

    mail.send(send_verification_email(current_user))
    flash('A verification email has been sent.', 'success')
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # current_user працює лише з Flask-Login, а ти його не підключив.
    # В результаті current_user тут буде None або помилковий об'єкт.
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).one_or_none()
    # Критична помилка: логіка перевірки паролю перевернута.
    # Якщо пароль правильний, умова повертає помилку.
    if not user or check_password_hash(user.password, password) != True:
        return jsonify({'message': 'Username or password is invalid!'}), 401

    response = jsonify({'message': 'Logged in successfully!'})
    access_token = create_access_token(identity=username, expires_delta=True)
    set_access_cookies(response, access_token)
    # Тут ти вдруге обгортаєш response у jsonify. Це помилка.
    return response


@app.route('/login_opt_protected', methods=['GET'])
@jwt_required(optional=True)
def optionally_protected():
    current_identity = get_jwt_identity()
    if current_identity:
        return jsonify(logged_in_as=current_identity), 200
    else:
        # Погане рішення: для "гостя" краще повертати 200 з відповідним текстом, а не 401.
        return jsonify(logged_id_as='guest'), 200


@app.route('/logout', methods=['POST'])
def logout():
    # Метод взагалі пустий.
    # Тут потрібно викликати unset_jwt_cookies(response),
    # інакше користувач не вийде з системи.
    if current_user.is_authenticated:
        response = jsonify({"msg": "logout successful"})
        unset_jwt_cookies(response)
        return response

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.get_reset_token()
            send_reset_password_email(user, token)
        flash('Check your email for reset instructions.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if not user:
        flash('Invalid or expired token', 'warning')
        return redirect(url_for('reset_password_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        new_password = form.password.data
        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@app.route('/edit_profile', methods=['PUT'])
@jwt_required(optional=False)
def edit_profile():
    form = EditForm()
    if form.validate_on_submit():
        username = request.form.get('username')
        address = request.form.get('address')
        if not username or not address:
            return jsonify({'error': 'Username or Address is invalid!'}), 401
        # Тут перевірка зроблена неправильно. Ти створюєш нового користувача,
        # замість того, щоб оновити дані існуючого.
        if username != current_user.username and username == User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username is already exist'}), 401
        # Тут ти створюєш нового користувача і додаєш у базу,
        # замість редагування current_user.
        current_user.username = username
        current_user.address = address
        db.session.commit()
        return jsonify({'message': 'User has been updated!'}), 200


if __name__ == '__main__':
    app.run()
