import base64
import os
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
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, \
    BestAvailableEncryption
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature

from OpenSSL import crypto

import requests
from flask import Flask, jsonify, request, render_template


class Registration:

    def __init__(self,  applicant_hkid, applicant_first_name, applicant_last_name, applicant_email, argms):
        self.blockchain = ''
        self.args = argms
        self.applicant_hkid = applicant_hkid
        self.applicant_first_name = applicant_first_name
        self.applicant_last_name = applicant_last_name
        self.applicant_email = applicant_email
        self.address = "http://127.0.0.1:" + str(args.port)
        # self.value = value
        self.public_key, self.private_key = self.generate_keypair('ecc', 'secp256r1', argms.admin_pass)
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

    def generate_voucher_keys(self, voucher_number, voucher_value):
            # key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            # private_key = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
            #                                 encryption_algorithm=NoEncryption())
            # public_key = key.public_key().public_bytes(encoding=Encoding.PEM,
            #                                            format=PublicFormat.SubjectPublicKeyInfo)
            #
            # # prk = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
            # # puk = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)
            #
            random_gen = Crypto.Random.new().read
            private_key = RSA.generate(4096, random_gen)
            public_key = private_key.publickey()

            voucher = OrderedDict({'voucher': voucher_number,
                            'value': voucher_value,
                            'rsa_public': private_key,
                            'rsa_private': public_key,
                            # 'applicant_public_key': self.public_key
                            })
            self.vouchers.append(voucher)

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
            return puk, prk


app = Flask(__name__)
registration = []

@app.route('/')
def index():
    return render_template('./make_registration.html')


@app.route('/use/voucher')
def make_transaction():
    return render_template('./use_voucher.html')


@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')



@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii'),
    }

    return jsonify(response), 200


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


@app.route('/generate/registration', methods=['POST'])
def generate_registration():
    applicant_hkid = request.form['applicant_hkid']
    applicant_first_name = request.form['applicant_first_name']
    applicant_last_name = request.form['applicant_last_name']
    applicant_email = request.form['applicant_email']

    global registration
    registration = Registration(applicant_hkid, applicant_first_name, applicant_last_name, applicant_email, args)

    pubkey_bytes = crypto.dump_publickey(crypto.FILETYPE_PEM, registration.public_key).decode('utf8')

    print("Original {}".format(pubkey_bytes))
    ele = pubkey_bytes.replace('\n','\\n')
    print(ele)
    response = {'registration': registration.to_dict_reg(), 'public_key': ele,
                'sender_address': registration.address, 'receiver_address': "http://127.0.0.1:5000",
                'signature': registration.sign_registration()}

    print(response)

    return jsonify(response), 200

@app.route('/generate/voucher', methods=['POST'])
def generate_voucher():
    voucher_number = request.form['voucher_number']
    voucher_value = request.form['voucher_value']
    approved_operator = request.form['approved_operator']

    registration.generate_voucher_keys(voucher_number,voucher_value)

    # Encrypt then send here not just signature

    pubkey_bytes = crypto.dump_publickey(crypto.FILETYPE_PEM, registration.vouchers[-1]["rsa_public_key"]).decode('utf8')

    print("Original {}".format(pubkey_bytes))
    ele = pubkey_bytes.replace('\n', '\\n')
    print(ele)
    response = {'registration': registration.to_dict_reg(), 'public_key': ele,
                'sender_address': registration.address, 'receiver_address': "http://127.0.0.1:5000",
                'signature': registration.sign_registration()}

    print(response)

    return jsonify(response), 200





if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    parser.add_argument('-a', '--admin_pass', default=b'test', help='Enter the password of admin')  # 9k8ov7oucher
    args = parser.parse_args()
    # registration = Registration('', 'applicant_first_name', 'applicant_last_name', 'applicant_email', args)

    app.run(host='127.0.0.1', port=args.port)
