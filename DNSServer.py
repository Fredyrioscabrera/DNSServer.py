import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data  

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

# --- PASO 1 Y 3: PARÁMETROS DE EXFILTRACIÓN ---
salt = b'Tandon' # [cite: 50]
password = "fr2498@nyu.edu" # [cite: 51]
input_string = "Always Watching" # [cite: 51]

encrypted_value = encrypt_with_aes(input_string, password, salt)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)

# --- PASO 4: DICCIONARIO DE REGISTROS DNS ---
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: ('ns1.example.com.', 'admin.example.com.', 2023081401, 3600, 1800, 604800, 86400),
    },
    'safebank.com.': { dns.rdatatype.A: '192.168.1.102' }, # [cite: 69]
    'google.com.': { dns.rdatatype.A: '192.168.1.103' }, # [cite: 69]
    'legitsite.com.': { dns.rdatatype.A: '192.168.1.104' }, # [cite: 69]
    'yahoo.com.': { dns.rdatatype.A: '192.168.1.105' }, # [cite: 70, 71]
    'nyu.edu.': { # [cite: 70, 72, 73]
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (str(encrypted_value),), # [cite: 74]
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')], # [cite: 76]
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312', # [cite: 77]
        dns.rdatatype.NS: 'ns1.nyu.edu.' # [cite: 79]
    }
}

def run_dns_server():
    # PASO 5: Crear socket UDP y bindearlo [cite: 81, 82]
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 53))

    while True:
        try:
            # PASO 6: Recibir datos [cite: 83]
            data, addr = server_socket.recvfrom(1024)
            # PASO 7: Parsear mensaje [cite: 84]
            request = dns.message.from_wire(data)
            # PASO 8: Crear respuesta [cite: 85, 86]
            response = dns.message.make_response(request)

            # PASO 9: Obtener la PRIMERA pregunta (índice 0, no 1024) 
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # PASO 10: Buscar en el diccionario [cite: 88]
            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                # PASO 11: Manejar tipos [cite: 89]
                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum)
                    rdata_list.append(rdata)
                else:
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, d) for d in answer_data]
                
                for rdata in rdata_list:
                    response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                    response.answer[-1].add(rdata)

            # PASO 12: Bandera AA (Authoritative Answer) [cite: 90]
            response.flags |= (1 << 10)

            # PASO 13: Enviar respuesta [cite: 93]
            server_socket.sendto(response.to_wire(), addr)
        except KeyboardInterrupt:
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            continue

def run_dns_server_user():
    input_thread = threading.Thread(target=lambda: [input(), os.kill(os.getpid(), signal.SIGINT)])
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()