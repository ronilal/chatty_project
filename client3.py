import tkinter as tk
import pickle
import hashlib
import socket
from tcp_by_size import recv_by_size, send_with_size
from stego import Encode, Decode
from display import display_image
from queue import Queue
import threading
import time
from PIL import Image, ImageTk


IP ='10.0.0.27'
PORT = 5435

class MyGui:
    def __init__(self, sock):
        self.sock = sock
        self.window = tk.Tk()

        self.label = tk.Label(self.window, text="Username:")
        self.label.pack(padx=20, pady=5)

        self.user = tk.Entry(self.window)
        self.user.pack(padx=20, pady=5)

        self.label2 = tk.Label(self.window, text="Password:")
        self.label2.pack(padx=20, pady=5)

        self.password = tk.Entry(self.window, show="*")
        self.password.pack(padx=20, pady=5)

        self.forget = tk.Button(self.window, text='Sign Up!', command=self.SignUpMsg)
        self.forget.pack(padx=20, pady=5)

        self.button = tk.Button(self.window, text='Forgot Password?', command=self.forget_pass_msg)
        self.button.pack(padx=20, pady=5)

        self.button = tk.Button(self.window, text='Enter', command=self.login)
        self.button.pack(padx=20, pady=5)

        self.window.mainloop()

    def send_message(self):
        message = self.msg_entry.get()
        if message.strip() != "":
            self.msgReq(self.username,message.encode())
            print("b s")
            print("recieved")
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, "You: " + message + "\n")
            self.chat_display.config(state=tk.DISABLED)
            self.msg_entry.delete(0, tk.END)

        else:
            print("server is not in msg state")

    def receive_messages(self):
        while True:
            try:
                message = recv_by_size(self.sock, return_type='byte')
                print("s")
                user_data = pickle.loads(message)
                if message:
                    sender = user_data['sender']
                    if user_data['code'] == 'sending':
                        msg = user_data['msg'].decode()

                        self.message_queue.put(msg)
                        self.senders_queue.put(sender)

                    elif user_data['code'] == 'pic':
                        print("pic recived")
                        self.sent_image = pickle.loads(user_data['msg'])
                        self.ask_image_page(sender)

            except Exception as e:
                print("Error:", e)
                break

    def check_messages(self):
        while True:
            if not self.message_queue.empty():
                message = self.message_queue.get()
                self.chat_display.config(state=tk.NORMAL)
                self.chat_display.insert(tk.END,self.senders_queue.get() + ": " + message + "\n")
                self.chat_display.config(state=tk.DISABLED)

            time.sleep(1)  # Adjust sleep duration as needed
    def home_page(self):
        # Create main window
        self.home = tk.Tk()
        self.home.title("Chatroom")

        # Create chat display
        self.chat_display = tk.Text(self.home, width=50, height=20, state=tk.DISABLED)
        self.chat_display.pack()

        # Create message entry
        self.msg_entry = tk.Entry(self.home, width=50)
        self.msg_entry.pack()

        # Create send button
        send_button = tk.Button(self.home, text="Send", command=self.send_message)
        send_button.pack()

        sendPic_button = tk.Button(self.home, text="Send Picture", command=self.send_picture_page)
        sendPic_button.pack()

        self.message_queue = Queue()
        self.senders_queue = Queue()

        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()

        check_messages_thread = threading.Thread(target=self.check_messages)
        check_messages_thread.start()

        # Start the main event loop
        self.home.mainloop()
    def login(self):
        self.username = self.user.get()
        password = self.password.get()
        self.loginReq(self.username,password)

        serv_msg = recv_by_size(self.sock)
        if serv_msg == 'logged in':
            close_window(self.window)
            self.home_page()
        elif serv_msg == 'logged out':
            print("invalid password or username")
        else:
            print("error")
    def send_picture_page(self):
        self.sendPic = tk.Tk()

        self.SPlabel = tk.Label(self.sendPic, text="Please enter image path")
        self.SPlabel.pack(padx=20, pady=5)

        self.SPpath = tk.Entry(self.sendPic)
        self.SPpath.pack(padx=20, pady=5)

        SPbutton = tk.Button(self.sendPic, text="enter", command=self.display_image)
        SPbutton.pack()

        self.sendPic.mainloop()

    def loginReq(self,username,password):
        login_dict = {
            "code": 'login',
            "user": username,
            "password": password
        }
        data = pickle.dumps(login_dict)
        send_with_size(self.sock, data)
        return

    def signupReq(self,username,password,email):
        signup_dict = {
            "code": 'signup',
            "user": username,
            "password": password,
            'email': email
        }
        data = pickle.dumps(signup_dict)
        send_with_size(self.sock, data)
        return

    def forgotReq(self,username,email):
        forgot_dict = {
            "code": 'forgot',
            "user": username,
            "email": email
        }
        data = pickle.dumps(forgot_dict)
        send_with_size(self.sock, data)
        return

    def msgReq(self,username,msg):
        msg_dict = {
            "code": 'msg',
            "user": username,
            "msg": msg
        }
        data = pickle.dumps(msg_dict)
        send_with_size(self.sock, data)
        return

    def ask_image_page(self,sender):
        print("ask image")
        self.ask_image = tk.Tk()
        self.ask_image.title("Image Display")

        label = tk.Label(self.ask_image, text = sender + " sent a picture, do you want to see it?")
        label.pack()

        button = tk.Button(self.ask_image, text="yes", command=self.show_sent_pic)
        button.pack()

        button2 = tk.Button(self.ask_image, text="no", command=self.close_it)
        button2.pack()

        self.ask_image.mainloop()

    def close_it(self):
        close_window(self.ask_image)

    def close_it2(self):
        close_window(self.image_page2)
        self.close_it()

    def close_it3(self):
        close_window(self.secret)

    def show_sent_pic(self):

        # Convert the image for Tkinter
        self.tk_image2 = ImageTk.PhotoImage(self.sent_image)

        # Create a Tkinter window
        self.image_page2 = tk.Tk()
        self.image_page2.title("Image Display")

        # Create a label widget to display the image
        label = tk.Label(self.image_page2, image=self.tk_image2)
        label.pack()

        button = tk.Button(self.image_page2, text="close", command=self.close_it2)
        button.pack()

        button = tk.Button(self.image_page2, text="check for secret message", command=self.secret_msg)
        button.pack()

        self.image_page2.mainloop()

    def secret_msg(self):
        data = Decode(self.sent_image)
        self.secret = tk.Tk()
        self.secret.title("Image Display")

        # Create a label widget to display the image
        label = tk.Label(self.secret, text=data)
        label.pack()

        button = tk.Button(self.secret, text="close", command=self.close_it3)
        button.pack()


    def display_image(self):

        self.Image_path = self.SPpath.get()
        self.image = Image.open(self.Image_path)

        self.secret1 = tk.Tk()
        self.secret1.title("Image Display")

        # Create a label widget to display the image
        label = tk.Label(self.secret1, text='enter "send" to send and "encode" to add a secret')
        label.pack()

        self.Emessage = tk.Entry(self.secret1)
        self.Emessage.pack(padx=20, pady=5)

        Ebutton = tk.Button(self.secret1, text="enter", command=self.check_input)
        Ebutton.pack()

        close_window(self.sendPic)

        self.secret1.mainloop()

    def check_input(self):
        data = self.Emessage.get()

        if data == 'send':
            self.send_picture()
        else:
            self.encode_page()

    def send_picture(self):
        data ={
            'code' : 'pic',
            'picture' : pickle.dumps(self.image)
        }
        encrypted_data = pickle.dumps(data)
        send_with_size(self.sock, encrypted_data)
        close_window(self.secret1)

    def encode_page(self):
        self.encode_root = tk.Tk()

        self.Elabel = tk.Label(self.encode_root, text="Please enter the secret message")
        self.Elabel.pack(padx=20, pady=5)

        self.Emessage = tk.Entry(self.encode_root)
        self.Emessage.pack(padx=20, pady=5)

        Ebutton = tk.Button(self.encode_root, text="enter", command=self.encode_pic)
        Ebutton.pack()

        self.sendPic.mainloop()
    def encode_pic(self):
        self.image = Encode(self.Image_path,self.Emessage.get())
        self.send_picture()



    def forgot_password(self):
        username = self.user_entry.get()
        email = self.email_entry.get()
        self.forgotReq(username,email)
        data = recv_by_size(self.sock)
        if data != 'email sent':
            print("email not send start over")
        self.VcodeMsg()
        data = recv_by_size(self.sock)
        if data == 'code verified':
            self.change_password_msg()

    def change_password(self):
        self.sendInfoChange()
        data = recv_by_size(self.sock)
        if data == 'password changed':
            print("password changed")
        else:
            print("password changed failed")

        close_window(self.change_pass)


    def change_password_msg(self):

        self.change_pass = tk.Tk()

        self.newpass_label = tk.Label(self.change_pass, text="new password:")
        self.newpass_label.pack(padx=20, pady=5)

        self.newpass_entry = tk.Entry(self.change_pass)
        self.newpass_entry.pack(padx=20, pady=5)

        # Button to submit username and email
        self.submit2_button = tk.Button(self.change_pass, text="Submit", command=self.change_password)
        self.submit2_button.pack(padx=20, pady=10)

        self.change_pass.mainloop()


    def forget_pass_msg(self):
        # Create the forget_pass window
        self.forgot_pass = tk.Tk()

        # Labels and Entry widgets for username and email
        self.user_label = tk.Label(self.forgot_pass, text="Username:")
        self.user_label.pack(padx=20, pady=5)

        self.user_entry = tk.Entry(self.forgot_pass)
        self.user_entry.pack(padx=20, pady=5)

        self.email_label = tk.Label(self.forgot_pass, text="Email:")
        self.email_label.pack(padx=20, pady=5)

        self.email_entry = tk.Entry(self.forgot_pass)
        self.email_entry.pack(padx=20, pady=5)

        # Button to submit username and email
        self.submit_button = tk.Button(self.forgot_pass, text="Submit", command=self.forgot_password)
        self.submit_button.pack(padx=20, pady=10)

    def SignUpMsg(self):
        self.Swindow = tk.Tk()

        self.SuserL = tk.Label(self.Swindow, text="Username:")
        self.SuserL.pack(padx=20, pady=5)

        self.Suser = tk.Entry(self.Swindow)
        self.Suser.pack(padx=20, pady=5)

        self.SpasswordL = tk.Label(self.Swindow, text="Password:")
        self.SpasswordL.pack(padx=20, pady=5)

        self.Spassword = tk.Entry(self.Swindow, show="*")
        self.Spassword.pack(padx=20, pady=5)

        self.SConPassL = tk.Label(self.Swindow, text="Password again:")
        self.SConPassL.pack(padx=20, pady=5)

        self.SConPass = tk.Entry(self.Swindow, show="*")
        self.SConPass.pack(padx=20, pady=5)

        self.SEmailL = tk.Label(self.Swindow, text="Email:")
        self.SEmailL.pack(padx=20, pady=5)

        self.SEmail = tk.Entry(self.Swindow)
        self.SEmail.pack(padx=20, pady=5)

        self.Ssign = tk.Button(self.Swindow, text='Sign Up!', command=self.SignUp)
        self.Ssign.pack(padx=20, pady=5)

        self.Swindow.mainloop()


    def VcodeMsg(self):
        self.CodeW = tk.Tk()

        self.Vcode = tk.Label(self.CodeW, text="enter verification code")
        self.Vcode.pack(padx=20, pady=5)

        self.code = tk.Entry(self.CodeW)
        self.code.pack(padx=20, pady=5)

        self.enterCode = tk.Button(self.CodeW, text='next', command=self.send_verification_code)
        self.enterCode.pack(padx=20, pady=5)

        self.CodeW.mainloop()



    def send_verification_code(self):
        code = self.code.get()
        send_with_size(self.sock,code.encode())
        close_window(self.CodeW)


    def CheckConPass(self):
        password = self.Spassword.get()
        password2 = self.SConPass.get()
        return password == password2

    def hash_password(self, password, salt, pepper='M'):
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        pepper_bytes = pepper.encode('utf-8')
        hashed_password = hashlib.sha256(password_bytes + salt_bytes + pepper_bytes).hexdigest()
        return hashed_password

    def SignUp(self):
        if self.CheckConPass():
            user = self.Suser.get()
            password = self.Spassword.get()
            email = self.SEmail.get()
            self.signupReq(user,password,email)

            data = recv_by_size(self.sock)
            if data == 'email sent':
                self.VcodeMsg()
            else:
                print("email not sent close application")

            data2 = recv_by_size(self.sock)
            if data2 == 'code unverified':
                print("code is incorrect")



            serv_msg = recv_by_size(self.sock)
            if serv_msg == 'signed up':
                print("done")
            elif serv_msg == 'signed down':
                print("username taken")
            else:
                print("error")
        else:
            print("Passwords do not match")


def close_window(window):
    # Call the quit() method to stop the main loop
    window.quit()

    # Destroy the window
    window.destroy()


def main(ip, port):
    sock = socket.socket()
    sock.connect((ip, port))
    print("server connected")
    root = MyGui(sock)

main(IP, PORT)
