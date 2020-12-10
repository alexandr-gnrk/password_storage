import string
import re
import secrets

from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for
)

from kms import KMS
import orm


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

        print(login, password)
        print(type(login), type(password))

        user = orm.check_credential(login, password)
        print(user)
        if user is None:
            return render_template('login.html', wrong_password=True)
        else:
            nonce = bytes.fromhex(user.nonce)
            
            global kms
            mobile_phone_hash = kms.decrypt(
                user.login, 
                user.mobile_phone_hash,
                nonce)
            mobile_phone_hash = mobile_phone_hash.decode(encoding='ascii')
            
            session['user'] = {
                'login': user.login,
                'full_name': user.full_name,
                'email': user.email,
                'mobile_phone': mobile_phone_hash
            }
            print(session)
            return redirect(url_for('profile'))

    return render_template('login.html')


@app.route('/profile')
def profile():
    if session['user'] is None:
        return redirect(url_for(login))
    return render_template('profile.html', user=session['user'])


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        full_name = request.form['full_name']
        email = request.form['email']
        mobile_phone = request.form['mobile_phone']

        if not check_password(password):
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


def check_password(pwd):
    password_re =  re.compile(r'''(
        ^(?=.*[A-Z].*[A-Z])                # at least two capital letters
        (?=.*[!@#$&*])                     # at least one of these special c-er
        (?=.*[0-9].*[0-9])                 # at least two numeric digits
        (?=.*[a-z].*[a-z].*[a-z])          # at least three lower case letters
        .{8,}                              # at least 8 total digits
        $
        )''', re.VERBOSE)
    
    if not password_re.search(pwd):
        return False
    return True
        

if __name__ == '__main__':
    app.run(debug=True)

