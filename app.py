import secrets
import ssl

from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for
)

from kms import KMS
import orm
import paswd

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

kms = KMS()


@app.route('/')
def root():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        user = orm.check_credential(login, password)
        if user is None:
            return render_template('login.html', wrong_password=True)
        else:
            session['user'] = adapt_user(user)
            return redirect(url_for('profile'))

    return render_template('login.html')


@app.route('/profile', defaults={'login': None})
@app.route('/profile/<login>')
def profile(login):
    adapted_user = None
    if not(login is None):
        user = orm.get_user(login)
        if not(user is None):
            adapted_user = adapt_user(user)
    else:
        adapted_user = session.get('user', None)

    if adapted_user is None:
        return redirect(url_for('login'))

    return render_template('profile.html', user=adapted_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        full_name = request.form['full_name']
        email = request.form['email']
        mobile_phone = request.form['mobile_phone']

        if not paswd.ensure_not_common(password):
            err_message = 'Your can not use common used password. Try to make it harder.'
            return render_template('register.html', err_message=err_message)
        elif not paswd.ensure_hard(password):
            err_message = ('Your password should have at least one special charachter,'+
                'two digits, two uppercase and three lowercase charachter. Length: 8+ characters.')
            return render_template('register.html', err_message=err_message)

        global kms
        kms.create_DEK(login)
        nonce = kms.generate_nonce()
        mobile_phone_hash = kms.encrypt(
            login, 
            bytes(mobile_phone, encoding='ascii'),
            nonce)

        orm.create_user(
            full_name, email, login, password, 
            mobile_phone_hash.hex(), nonce.hex())
        return redirect(url_for('login'))

    return render_template('register.html')


def adapt_user(user):
    global kms
    mobile_phone_hash = kms.decrypt(
        user.login, 
        bytes.fromhex(user.mobile_phone_hash),
        bytes.fromhex(user.nonce))
    mobile_phone_hash = mobile_phone_hash.decode(encoding='ascii')
    
    return {
        'login': user.login,
        'full_name': user.full_name,
        'email': user.email,
        'mobile_phone': mobile_phone_hash
    }

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain('./data/cert.crt', './data/key.pem')
    app.run(debug=False, ssl_context=context)

# User example
# 
# Login: alexandr
# Password: !11QQqqqw
# 
# Login: ibah
# Password: 11He!Tq2ps
