import base64
import json
import os
import re
import string
import traceback
from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
import yaml
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.kdf import x963kdf
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, \
    BestAvailableEncryption, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature

from OpenSSL import crypto

import requests
from flask import Flask, jsonify, request, render_template, Response, flash, redirect, url_for, session, logging
from flask_cors import CORS

from flaskext.mysql import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from wtforms.validators import ValidationError
from passlib.hash import sha256_crypt, sha512_crypt
from functools import wraps

import verify as vf
import safe

import pymysql


class Registration:

    def __init__(self, applicant_hkid, applicant_first_name, applicant_last_name, applicant_email, argms):
        self.blockchain = []
        self.args = argms
        self.applicant_hkid = applicant_hkid
        self.applicant_first_name = applicant_first_name
        self.applicant_last_name = applicant_last_name
        self.applicant_email = applicant_email
        self.address = "http://127.0.0.1:" + str(args.port)
        # self.value = value
        self.public_key, self.private_key, self.main_key = self.generate_keypair('ecc', 'secp256r1', argms.admin_pass)
        self.vouchers = []

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict_trans(self):
        return OrderedDict({'applicant_first_name': self.applicant_first_name,
                            'applicant_last_name': self.applicant_last_name,
                            'value': self.value})

    def to_dict_reg(self):
        return OrderedDict({'applicant_first_name': self.applicant_first_name,
                            'applicant_last_name': self.applicant_last_name,
                            'applicant_hkid': self.applicant_hkid,
                            'applicant_email': self.applicant_email,
                            # 'applicant_public_key': self.public_key
                            })

    def json_to_byteskey(self, key):
        return (str.encode(key)).replace(b'\\n', b'\n')

    def verify_transaction_signature(self, transaction_data, sender_public_key, signature):
        """
        Check that the provided signature corresponds to transaction
        signed by the public key (sender_address)
        """
        # No need since already in bytes
        signature = binascii.unhexlify(signature)

        # signature = binascii.unhexlify(str(signature).encode('utf8'))
        data = str(transaction_data).encode('utf8')
        public_key = self.json_to_byteskey(sender_public_key)
        # print("DATA", data)
        # print("BabSIGNA", signature)
        # print("PUBK", public_key)

        puk = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)
        x509 = crypto.X509()
        x509.set_pubkey(puk)

        # ans = crypto.verify(x509, signature, data, 'sha256')
        try:
            crypto.verify(x509, signature, data, 'sha256')
            print('Verification OK')
        except InvalidSignature:
            print('Verification failed')
        return crypto.verify(x509, signature, data, 'sha256')

        # if crypto.verify(x509, signature, data, 'sha256') is None:
        #     print('Verification OKK')
        # else:
        #     print('Verification failedd')
        #
        # return crypto.verify(x509, signature, data, 'sha256')

    def sign_transaction(self):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict_trans()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    def sign_registration(self):
        """
        Sign transaction with private key
        """
        # try:
        #     pkey_path = './data/client/private.pem'
        #     private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(pkey_path, 'rb'))
        # except IOError:
        #     print("Unable to locate key file {}".format(pkey_path))
        # print('We have')
        # print(private_key)
        data = str(self.to_dict_reg()).encode('utf8')
        signature = crypto.sign(pkey=self.private_key, data=data, digest='sha256')
        # Verify
        # the verify() function expects that the public key is
        # wrapped in an X.509 certificate
        print()
        x509 = crypto.X509()
        x509.set_pubkey(self.public_key)
        print(self.private_key)
        print(self.public_key)
        print(data)
        print(signature)

        try:
            crypto.verify(x509, signature, data, 'sha256')
            print('Verification OK')
        except InvalidSignature:
            print('Verification failed')
        # print('First')
        # print(signature)
        # print('Second')
        # print(base64.b64encode(signature))
        # print('Third')
        # print(binascii.hexlify(signature).decode('ascii'))
        # problem with public key that you send not the signature
        return binascii.hexlify(signature).decode('ascii')

    def sign_voucher(self, voucher):
        """
        Sign voucher with private key
        """
        data = str(voucher).encode('utf8')
        signature = crypto.sign(pkey=self.private_key, data=data, digest='sha256')
        # Verify
        # the verify() function expects that the public key is
        # wrapped in an X.509 certificate
        x509 = crypto.X509()
        x509.set_pubkey(self.public_key)
        # print("PUK", crypto.dump_publickey(crypto.FILETYPE_PEM,self.public_key))
        # print("DATA", data)
        # print("SISI", signature)

        try:
            crypto.verify(x509, signature, data, 'sha256')
            print('Verification OK')
        except InvalidSignature:
            print('Verification failed')
        return binascii.hexlify(signature).decode('ascii')

    def generate_keypair(self, hash_type, key_size_curve, admin):
        try:
            with open('./config.yaml') as f:
                config = yaml.load(f, Loader=yaml.FullLoader)
        except FileNotFoundError:
            print('ERROR in reading config file: ')
            traceback.print_exc()

        os.makedirs(config['public_root'], exist_ok=True)

        # Check type of hash function
        for nodecfg in config['client']:
            key_size_curve = key_size_curve.lower()
            if hash_type.lower() == 'rsa':
                if key_size_curve in ['1024', '2048', '4096']:
                    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size_curve)
                else:
                    print('Unsupported key curve: ' + key_size_curve + '\n')
                    return None

            else:
                if key_size_curve not in ['secp256r1', 'secp384r1', 'secp521r1']:
                    print('Unsupported key curve: ' + key_size_curve + '\n')
                    return None
                if key_size_curve == 'secp256r1':
                    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                elif key_size_curve == 'secp384r1':
                    key = ec.generate_private_key(ec.SECP384R1(), default_backend())
                elif key_size_curve == 'secp521r1':
                    key = ec.generate_private_key(ec.SECP521R1(), default_backend())

                if nodecfg['type'] == 'client':
                    private_key = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=NoEncryption())
                else:
                    private_key = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=NoEncryption())
                    # private_key = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
                    #                                 encryption_algorithm=BestAvailableEncryption(password=admin))

            public_key = key.public_key().public_bytes(encoding=Encoding.PEM,
                                                       format=PublicFormat.SubjectPublicKeyInfo)

            prk = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
            puk = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)
            os.makedirs(nodecfg['root'], exist_ok=True)
            print()
            print('1z')
            print(public_key)
            # print(private_key,public_key)
            # print(prk,puk)
            # print(base64.b64encode(private_key))
            # print(base64.b64encode(public_key))
            # print()
            # print()
            # print((base64.b64encode(private_key)).decode('ascii'))
            # print(private_key)

            # Same output as public_key
            # print(crypto.dump_publickey(crypto.FILETYPE_PEM, puk))

            with open(os.path.join(nodecfg['root'], 'private.pem'), 'wb') as private_file_f:
                private_file_f.write(private_key)
            with open(os.path.join(config['public_root'], '{}.pub.pem'.format(nodecfg['id'])),
                      'wb') as public_file_f:
                public_file_f.write(public_key)

            # print(public_key)
            # print('The other public key is ' + binascii.hexlify(public_key).decode('ascii'))
            print('Returned public key')
            return puk, prk, key

    def decrypt_sign(self, key, signature):
        # Key is same as sender_private_key
        message = binascii.unhexlify(str(signature).encode('utf8'))
        backend = default_backend()

        point = message[0:65]
        tag = message[65:81]
        ciphertext = message[81:]
        print("The point", point)
        print("The encryptor", tag)
        print("The ciphertext", ciphertext)

        key = self.json_to_byteskey(key)

        receiver_private_key = self.main_key

        sender_public_key = load_pem_public_key(key)
        shared_key = receiver_private_key.exchange(ec.ECDH(), sender_public_key)

        # print("SHared", shared_key)
        iv = '000000000000'
        xkdf = x963kdf.X963KDF(
            algorithm=SHA256(),
            length=32,
            sharedinfo=''.encode(),
            backend=backend
        )
        key = xkdf.derive(shared_key)
        decryptor = Cipher(
            AES(key),
            modes.GCM(iv.encode(), tag),
            backend=backend
        ).decryptor()
        message = decryptor.update(ciphertext) + decryptor.finalize()
        print("Decrypted message", message)
        # print(sender_private_key, sender_public_key)
        # print()
        # print(receiver_private_key, receiver_public_key
        return message

    def add_voucher(self, sender_public_key, receiver_public_key, sender_address, receiver_address,
                    voucher_number, value, signature):

        if len(self.vouchers) > 20:
            return len(self.vouchers)

        # Make voucher template
        voucher = OrderedDict({'sender_public_key': sender_public_key,
                               'receiver_public_key': receiver_public_key,
                               'sender_address': sender_address,
                               'receiver_address': receiver_address,
                               'voucher_number': voucher_number,
                               'value': value})
        # Retrieve server public key from blockchain
        server_public_key = self.blockchain["chain[0][transactions][0][sender_public_key]"]
        print("The server public key", server_public_key)
        decrypted_signature = self.decrypt_sign(key=server_public_key, signature=signature)
        # The decrypted signature is a binary of the signnature, hence we must trime it
        voucher_verification = self.verify_transaction_signature(transaction_data=voucher,
                                                                 sender_public_key=server_public_key,
                                                                 signature=decrypted_signature)
        print("Voucher num", voucher_number)
        print("Decrypted signa", decrypted_signature)
        print("Sent Decrypted signa", binascii.hexlify(decrypted_signature).decode('ascii'))
        print("Sent DoubleDecrypted signa",
              binascii.unhexlify(str(binascii.hexlify(decrypted_signature).decode('ascii')).encode("utf8")))
        if voucher_verification is None:
            print("Confirmed Signature Transaction!")
            client_signature = self.sign_voucher(voucher)

            voucher = OrderedDict({'voucher_data': voucher,
                                   'signature_client': client_signature,
                                   'signature_server': binascii.hexlify(decrypted_signature).decode('ascii')})

            # print("Added voucher", voucher["signature_client"])
            # print("Added voucher1", voucher["voucher_data"]["value"])
            # print("Added voucher", voucher["voucher_data"]["value"])
            self.vouchers.append(voucher)
            return len(self.vouchers) + 1
        else:
            return False

        # sender_public_key = sender_private_key.public_key()
        # receiver_private_key = ec.generate_private_key(ec.SECP256K1(), backend)
        # receiver_public_key = receiver_private_key.public_key()
        #
        # shared_key1 = sender_private_key.exchange(ec.ECDH(), receiver_public_key)
        # shared_key2 = receiver_private_key.exchange(ec.ECDH(), sender_public_key)
        #
        # if shared_key1==shared_key2:
        #     print("The shared keys are {} and \n {}".format(shared_key1,shared_key2))
        # else:
        #     print("NOPE")


class RegisterForm(Form):
    firstname = StringField('First Name:', [validators.Length(min=1, max=50), validators.DataRequired()])
    lastname = StringField('Last Name:', [validators.Length(min=1, max=50), validators.DataRequired()])
    hkid = StringField('HKID:', [validators.Length(min=6, max=10), validators.DataRequired()])
    email = StringField('Email:', [validators.Length(min=6, max=50), validators.DataRequired()])
    password = PasswordField('Password:', [
        validators.DataRequired(),
        validators.Length(min=8, max=50)
    ])

    # def validate_hkid(form, field):
    #     if not vf.verify(field.data):
    #         raise ValidationError('HKID is not valid')

    # def validate_password(form, field):
    #     print("Fielddd", field.data)
    #     regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
    #     if not (any(char.islower() for char in field.data)):
    #         print("low")
    #         raise ValidationError('Password must contain lowercase letters')
    #     if not (any(char.isupper() for char in field.data)):
    #         print("upp")
    #         raise ValidationError('Password must contain uppercase letters')
    #     if not (any(char.isdigit() for char in field.data)):
    #         print("digit")
    #         raise ValidationError('Password must contain digits')
    #     if regex.search(field.data) is None:
    #         print("spec")
    #         raise ValidationError('Password must contain special characters')
    #     if not safe.check(field.data).valid:
    #         print("common")
    #         raise ValidationError('Password is commonly used, please try another one')
    #     print("ALL IS WELL")


registration = []

app = Flask(__name__)
CORS(app)
# Config MySQL
# Password: secret

app.config['MYSQL_DATABASE_HOST'] = "localhost"
app.config['MYSQL_DATABASE_USER'] = "root"
app.config['MYSQL_DATABASE_PASSWORD'] = "voucherapp"  # voucherapp
app.config['MYSQL_DATABASE_DB'] = "voucher"
app.config['MYSQL_DATABASE_CURSORCLASS'] = "DictCursor"
app.secret_key = "secret"

# Init MySQL
mysql = MySQL(app, cursorclass=pymysql.cursors.DictCursor)
mysql.init_app(app=app)

voucher_page = './blocked_voucher.html'


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('./make_registration.html')
    # cur = mysql.connect().cursor()
    # form = RegisterForm(request.form)
    # print("The form is ", request.form)
    # if request.method == 'POST':
    #     print("POST method")
    #     if form.validate():
    #         print("INSIDE BABY")
    #         firstname = form.firstname.data
    #         lastname = form.lastname.data
    #         hkid = form.hkid.data
    #         email = form.email.data
    #         print("firstname etc", firstname, lastname, hkid, email)
    #
    #         password_hash = sha512_crypt.hash(str(form.password.data))  # Salt automatically generated
    #
    #         cur = mysql.connect().cursor()
    #         cur.execute("INSERT INTO users(firstname,lastname,email,hkid,password_hash) VALUES(%s,%s,%s,%s,%s)",
    #                     (firstname, lastname, email, hkid, password_hash))
    #
    #         mysql.connect().commit()
    #         cur.close()
    #
    #         flash('Your form has been submitted', 'success')  # pt2 min 29
    #         return redirect(url_for('index'))
    #     return render_template('./registration.html', form=form)
    # return render_template('./registration.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # email = request.form['email']
        hkid = request.form['hkid']
        password_candidate = request.form['password']

        # Add User to Database
        sql_insert = """SELECT * FROM users WHERE hkid = %s"""

        conn = mysql.connect()
        cursor = conn.cursor()
        try:
            result = cursor.execute(sql_insert, hkid)
            if result > 0:
                print("Found record",hkid,password_candidate)
                data = cursor.fetchone()
                password_hash = data['password_hash']
                # print("hash is",password_hash)
                # print("tentative is",sha512_crypt.hash(password_candidate))

                if sha512_crypt.verify(password_candidate, password_hash):
                    # Passed
                    session['logged_in'] = True
                    session['hkid'] = hkid
                    print("correct password")

                    flash('You are now logged in', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    error = 'Invalid password'
                    print(error)
                    cursor.close()
                    return render_template('./login.html', error=error)
            else:
                error = 'Username not found'
                return render_template('./login.html', error=error)
        except conn.IntegrityError:
            print("failed to insert values in Database")
        finally:
            cursor.close()

    return render_template('./login.html')


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))

    return wrap


@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

@app.route('/generate/registration', methods=['POST'])
def generate_registration():
    print("Received application ", request.form)
    applicant_hkid = request.form['applicant_hkid']
    applicant_first_name = request.form['applicant_first_name']
    applicant_last_name = request.form['applicant_last_name']
    applicant_email = request.form['applicant_email']
    password_hash = sha512_crypt.hash(request.form['applicant_password'])  # Salt automatically generated
    # return redirect(url_for('index'))

    global registration
    registration = Registration(applicant_hkid, applicant_first_name, applicant_last_name, applicant_email, args)
    pubkey_bytes = crypto.dump_publickey(crypto.FILETYPE_PEM, registration.public_key).decode('utf8')
    print("Original {}".format(pubkey_bytes))
    ele = pubkey_bytes.replace('\n', '\\n')
    print("Values",applicant_first_name, applicant_last_name, applicant_email, applicant_hkid, password_hash)

    # Add User to Database
    sql_insert = """INSERT INTO users(firstname,lastname,email,hkid,password_hash) VALUES(%s,%s,%s,%s,%s)"""

    conn = mysql.connect()
    cursor = conn.cursor()
    try:
        affected_count = cursor.execute(sql_insert, (applicant_first_name, applicant_last_name, applicant_email, applicant_hkid, password_hash))
        conn.commit()
        print("Affected_count %d", affected_count)
    except conn.IntegrityError:
        print("failed to insert values in Database")
    finally:
        cursor.close()

    # cur = mysql.connect().cursor()
    # cur.execute("INSERT INTO users(firstname,lastname,email,hkid,password_hash) VALUES(%s,%s,%s,%s,%s)",
    #             (applicant_first_name, applicant_last_name, applicant_email, applicant_hkid, password_hash))
    #
    # mysql.connect().commit()
    # cur.close()
    #
    # flash('Your form has been submitted', 'success')  # pt2 min 29

    # Send Response
    response = {'registration': registration.to_dict_reg(), 'public_key': ele,
                'sender_address': registration.address, 'receiver_address': "http://127.0.0.1:5000",
                'signature': registration.sign_registration()}

    print("Sent user",response)

    return jsonify(response), 200

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/use/voucher')
def use_voucher():
    return render_template(voucher_page)


@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')


# @app.route('/generate/transaction', methods=['POST'])
# def generate_transaction():
#     sender_address = request.form['sender_address']
#     sender_private_key = request.form['sender_private_key']
#     recipient_address = request.form['recipient_address']
#     value = request.form['amount']
#
#     transaction = Transaction(sender_address, sender_private_key, recipient_address, value)
#
#     response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}
#
#     return jsonify(response), 200



@app.route('/confirm/registration', methods=['POST'])
def confirm_generate_registration():
    return redirect(url_for('login'),code=307)
    # print("Value of url",request.base_url[:-21]+"/login")
    # log = requests.get(request.base_url[:-21]+"/login")
    # return "Transitioned", 200



@app.route('/generate_initial/voucher', methods=['POST'])
def generate_initial_voucher():
    print("The reque", request.form)
    voucher_number = int(request.form["voucher_number"])
    voucher = registration.vouchers[voucher_number - 1]

    print("Reg Vou", voucher)

    # approved_operator = request.form['approved_operator']

    response = voucher

    # print("FINAL res",response)
    return jsonify(response), 200


@app.route('/generate/voucher', methods=['POST'])
def generate_voucher():
    print("The reque", request.form)
    voucher_number = int(request.form["voucher_number"])
    voucher = registration.vouchers[voucher_number - 1]

    # print("Reg Vou", voucher)
    response = voucher

    # print("FINAL res", response)

    return jsonify(response), 200


@app.route('/receive/enc_vouchers', methods=['POST'])
def receive_vouchers():
    # Get encrypted voucher -> Decrypt using private key
    # Create signature(voucher),
    # Send voucher + signature + server_signature to operator
    values = request.form
    # print("THE VALUES ARE", values)

    # Check that the required fields are in the POST'ed data
    required = ['sender_public_key', 'receiver_public_key', 'sender_address',
                'receiver_address', 'voucher_number', 'value', 'signature']  # signature here is encrypted
    if not all(k in values for k in required):
        print('Values are missing')
        return 'Missing values', 400
    print("All values are here")
    # Create a new Transaction
    transaction_result = registration.add_voucher(values['sender_public_key'], values['receiver_public_key'],
                                                  values['sender_address'], values['receiver_address'],
                                                  values['voucher_number'], values["value"], values['signature'])

    if not transaction_result:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to Block ' + str(transaction_result)}
        return jsonify(response), 201


@app.route('/receive/chain', methods=['POST'])
def receive_chain():
    # Get encrypted voucher -> Decrypt using private key
    # Create signature(voucher),
    # Send voucher + signature + server_signature to operator
    values = request.form
    # print("THE VALUES of the chain ARE", values)

    registration.blockchain = values
    # print("The value of chain", values["chain[0][block_number]"])

    response = {'message': 'Chain retrieved !'}
    return jsonify(response), 201

@app.route('/allow/vouchers', methods=['GET', 'POST'])
def allow_vouchers():
    values = request.form
    print("Allowed voucher", values)
    global voucher_page
    voucher_page = './use_voucher.html'
    return 'Changed page', 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    parser.add_argument('-a', '--admin_pass', default=b'test', help='Enter the password of admin')  # 9k8ov7oucher
    args = parser.parse_args()
    # registration = Registration('', 'applicant_first_name', 'applicant_last_name', 'applicant_email', args)

    app.run(host='127.0.0.1', port=args.port)
