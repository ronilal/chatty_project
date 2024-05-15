import tkinter as tk
import pickle
import secrets
import hashlib
import socket
import threading
from tcp_by_size import recv_by_size, send_with_size
from stego import Encode, Decode
import random
import string
import time
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


users_dict = {}
PORT = 5458
msg_pending = False
threads = []
socks = []
# Set your SendGrid API key
SENDGRID_API_KEY = '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'

# Initialize the SendGrid client
sg = SendGridAPIClient(SENDGRID_API_KEY)

def login(sock,t,data):
    username = data['user']
    password = data['password']
    print(f"user {username} has logged in")

    # Load existing user data from the pickle file
    try:
        with open('data.pickle', 'rb') as f:
            users = pickle.load(f)
    except FileNotFoundError:
        users = {}

    # Check if username and password match
    if username in users:
        this_salt = users[username][1]
        hashed_password = hash_password(password, this_salt)
        if hashed_password == users[username][0]:
            send_with_size(sock, b'logged in')
        else:
            send_with_size(sock, b'logged out')
    else:
        send_with_size(sock, b'logged out')
        return

    userData = users[username]  # Updated to include email
    userData.append(username)
    newData = {t: userData}
    users_dict.update(newData)
    socks.append(sock)

def CheckConPass(password_entry, confirm_entry):
    password = password_entry.get()
    password2 = confirm_entry.get()
    return password == password2

def hash_password(password, salt, pepper='M'):
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    pepper_bytes = pepper.encode('utf-8')
    hashed_password = hashlib.sha256(password_bytes + salt_bytes + pepper_bytes).hexdigest()
    return hashed_password


def SignUp(sock,t, data):
    user = data['user']
    password = data['password']
    email = data['email']
    salt = generateSalt()
    data2 =0

    hashed_password = hash_password(password, salt)

    userData = [hashed_password, salt, email]  # Updated to include email
    newData = {user: userData}

    expiration_time = int(time.time()) + 300
    code = generate_verification_code()
    send_verification_email(userData[2],code,expiration_time,sock)
    try:
        client_code = recv_by_size(sock)
    except:
        close_client(sock,t)
        return
    if client_code == code:
        if is_code_within_time_limit(expiration_time):
            data2 = 'code verified'
            send_with_size(sock,b'code verified')
        else:
            send_with_size(sock,b'code unverified')
    else:
        send_with_size(sock, b'code unverified')


    # Load existing user data from the pickle file
    try:
        with open('data.pickle', 'rb') as f:
            users = pickle.load(f)
    except FileNotFoundError:
        users = {}

    # Check if username already exists
    if (user not in users) and (data2 == 'code verified'):
        users.update(newData)
        with open('data.pickle', 'wb') as f:
            pickle.dump(users, f)
        send_with_size(sock, b'signed up')
    else:
        send_with_size(sock, b'signed down')

def generateSalt(length=16):
    return secrets.token_hex(length)

def generate_verification_code():
    # Generate a 6-digit verification code
    return ''.join(random.choices(string.digits, k=6))

def send_verification_email(recipient_email, verification_code, expiration_time,socket):
    # Generate expiration time (5 minutes from now)

    # Email content
    subject = 'Verification Code'
    body = f'Your verification code is: {verification_code}. This code will expire at {time.ctime(expiration_time)}.'
    # Send email using send_email function
    sender_email = 'lalzarroni@gmail.com'
    send_email(sender_email, recipient_email, subject, body,socket)

def is_code_within_time_limit(expiration_time):
    current_time = int(time.time())
    return current_time <= expiration_time

def send_email(sender_email, recipient_email, subject, body,socket):
    # Create a Mail object
    message = Mail(
        from_email=sender_email,
        to_emails=recipient_email,
        subject=subject,
        html_content=body
    )

    try:
        # Send the email
        response = sg.send(message)
        send_with_size(socket,b'email sent')
    except Exception as e:
        print (e)
        send_with_size(socket,b'email not sent')

def Forgot(sock,t,data):
    global new_password
    user = data['user']
    email = data['email']
    if forget_code(sock,email,t):
        send_with_size(sock,b'code verified')
        try:
            new_password = recv_by_size(sock)
        except:
            close_client(sock,t)
        # Load existing user data from the pickle file
        try:
            with open('data.pickle', 'rb') as f:
                users = pickle.load(f)
        except FileNotFoundError:
            users = {}

        # Check if username already exists
        if (user in users):
            hashed_new =hash_password(new_password,users[user][1],'M')
            users[user][0]=hashed_new
            with open('data.pickle', 'wb') as f:
                pickle.dump(users, f)
            send_with_size(sock, b'password changed')
        else:
            send_with_size(sock, b'incorrect username')



def forget_code(sock,email,t):
    code = generate_verification_code()
    expiration_time = int(time.time()) + 300
    send_verification_email(email,code,expiration_time,sock)
    try:
        client_code = recv_by_size(sock)
    except:
        close_client(sock,t)
        return
    if client_code == code:
        if is_code_within_time_limit(expiration_time):
            return True

def broadcast(sock,msg,t,code):
    for socket in socks:
        print("in broadcst")
        if sock!=socket:
            data =0
            if code == 'pic':
                data = {
                    'code': code,
                    'sender': users_dict[t][3],
                    'msg': pickle.dumps(msg)
                }
            if code == 'sending':
                data = {
                    'code': code,
                    'sender': users_dict[t][3],
                    'msg': msg
                }
            pickled = pickle.dumps(data)
            try:
             send_with_size(socket,pickled)
            except:
                close_client(sock)
    return

def recieve_msg(sock,t,data):
    msg = data['msg']
    broadcast(sock,msg,t,'sending')

def recieve_pic(sock,t,data):
    print("at pic")
    image = pickle.loads(data['picture'])
    broadcast(sock,image,t,'pic')


def handle_req(request, sock,t, data):
    print("at handle req")
    print(request)
    if request == 'login':
        login(sock,t, data)
    elif request == 'signup':
        SignUp(sock,t, data)
    elif request == 'forgot':
        Forgot(sock,t, data)
    elif request == 'msg':
        recieve_msg(sock,t, data)
    elif request == 'pic':
        recieve_pic(sock,t, data)
    elif request == 'exit':
        close_client(sock,t)

def handle_client(sock, t, addr):
    while True:
        print("at handle client")
        try:
            data = recv_by_size(sock, return_type='byte')
            user_data = pickle.loads(data)
            code = user_data['code']
            handle_req(code, sock,t, user_data)
        except:
            close_client(sock,t)
            break
def close_client(sock,t):
    print(f"client number {t} has disconnected")
    sock.close()
    if sock in socks:
        socks.remove(sock)
def main(port):
    global all_to_die
    """
    main server loop
    1. accept tcp connection
    2. create thread for each connected new client
    3. wait for all threads
    4. every X clients limit will exit
    """
    srv_sock = socket.socket()

    srv_sock.bind(('0.0.0.0', port))

    srv_sock.listen(20)

    i = 1
    while True:
        print('\nMain thread: before accepting ...')
        cli_sock, addr = srv_sock.accept()
        print(f"client {i} has connected")
        t = threading.Thread(target=handle_client, args=(cli_sock, str(i), addr))
        t.start()
        i += 1
        threads.append(t)
        if i > 100000000:  # for tests change it to 4
            print('\nMain thread: going down for maintenance')
            break

# Create the main window
if __name__ == '__main__':
    main(PORT)
