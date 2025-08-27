from flask import render_template, url_for
from flask_mail import Message
from app import generate_verification_token

# Відправка пошти у цьому ж методі реєстрації робить функцію занадто громіздкою.
# Краще винести логіку у сервіс send_verification_email(user).
def send_verification_email(user, token):
    confirm_url = url_for('verify_email', token=token, _external=True)
    html = render_template('verify_email.html', confirm_url=confirm_url)

    msg = Message(subject='Please confirm your email',
                  sender='test@gmail.com',
                  recipients=[user.email],
                  body= render_template('text/verification_email.txt'),
                  html=html)
    return msg


def send_reset_password_email(user, token):
    msg = Message(
        sender='test@gmail.com',
        recipients=[user.email],
        body= render_template('text/reset_password.txt'),
        html=render_template('user/reset_password.html', user=user, token=token))

    return msg