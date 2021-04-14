from tkinter import *
import rsa
import socket
import threading
import time
import os
import os.path
import socks
import urllib.request
from zipfile import ZipFile



def check_tor():
	if 'Tor' in os.listdir():
		pass
	else:
		urllib.request.urlretrieve("https://www.torproject.org/dist/torbrowser/10.0.12/tor-win32-0.4.5.6.zip", 'tmp.zip')
		ZipFile('tmp.zip', 'r').extractall()
		os.popen("mkdir core")
		os.popen(".\\Tor\\tor.exe --service install")
		os.popen(".\\Tor\\tor.exe")
		time.sleep(8)
		os.popen("killall tor.exe")
myname = os.popen("whoami").read().split('\\')[1].replace("\n", "")


def tor_activation(port):
	tora = open("C:\\Users\\" + myname + "\\AppData\\Roaming\\tor\\torrc", "w")
	tora.write("HiddenServiceDir " + os.getcwd() + "\\core\nHiddenServicePort {port} 127.0.0.1:{port}".format(port=port))
	tora.close()
	threading.Thread(target=start_tor).start()
	print("ok1")
	time.sleep(16)
	
def start_tor():
	os.system(os.getcwd() + "\\Tor\\tor.exe")
	print("OURWR")

sock = socket.socket()

whoami = True

class Connection():
	def __init__(self, conn, addr):
		(self.pubkey, self.privkey) = rsa.newkeys(2048)
		print((self.pubkey, self.privkey))
		self.conn = conn
		self.addr = addr

	def make_secure_connection_for_server(self):
		
		conn.send(self.pubkey.save_pkcs1(format='DER'))
		print(0)
		self.client_pubkey = rsa.key.PublicKey.load_pkcs1(conn.recv(2048), format='DER')
		print(self.client_pubkey)


	def make_secure_connection_for_client(self):
		global sock
		socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050, True)
		sock = socks.socksocket()
		print(self.conn, self.addr)
		sock.connect((self.conn, self.addr))
		print("conn")
		self.server_pubkey = rsa.key.PublicKey.load_pkcs1(sock.recv(2048), format='DER')

		print(self.server_pubkey)
		sock.send(self.pubkey.save_pkcs1(format='DER'))



	def send_message_for_server(self, message):
		try:
			print("CRYPTING = " + message)
			senr = rsa.encrypt(bytes(message, 'utf-8'), self.client_pubkey)
			print(senr, "SENDING")
			conn.send(senr)
			
			return True
		except:
			return False

	def send_message_for_client(self, message):
		try:
			print("CRYPTING = " + message)
			senr = rsa.encrypt(bytes(message, 'utf-8'), self.server_pubkey)
			sock.send(senr)
			print(senr, "SENDING")
			return True
		except:
			return False

	def get_message_for_server(self):

		data = conn.recv(99999)
		if data == b'':
			return False
		else:

			print(data, 1)
			data = rsa.decrypt(data, self.privkey).decode("utf-8")
			print(data, 2)
			return data


	def get_message_for_client(self):
		global sock
		data = sock.recv(99999)
		print(data, 1)
		if data == b'':
			return False
		else:
			data = rsa.decrypt(data, self.privkey).decode("utf-8")
			print(data, 2)
			return data


	def close_by_server(self):
		try:
			conn.close()
			return True
		except:
			return False

	def close_by_client(self):
		try:
			sock.close()
			return True
		except:
			return False 

def fucking_function_for_server():
	while True:
		time.sleep(1)
		fucking_message = new_connection.get_message_for_server()
		if fucking_message != False:
			lbox.insert(END, 'Interlocutor: ' + fucking_message)
		else:
			pass

def fucking_function_for_client():
	while True:
		time.sleep(1)
		fucking_message = new_connection.get_message_for_client()
		if fucking_message != False:
			lbox.insert(END, 'Interlocutor: ' + fucking_message)
		else:
			pass

def send():
	message = txt.get()
	if message != "":
		lbox.insert(END, 'You: ' + message)
		lbox.yview(END)
		txt.delete(0, END)
		if whoami:
			new_connection.send_message_for_server(message)
		else:
			new_connection.send_message_for_client(message)
	else:
		pass
root = Tk()

def create_server():
	global conn, addr, new_connection
	servp = int(inputport.get())

	win2.destroy()
	print(7)


	check_tor()
	print(10)
	tor_activation(servp)
	print(11)
	file = open("okay_for_start.txt", "w")
	file.write('Okay Your host is {host}:{port} Waiting for clients...'.format(host=open(os.getcwd() + "\\core\\hostname", 'r').read(), port=servp))
	file.close()
	sock.bind(("127.0.0.1", servp))
	sock.listen(1)
	conn, addr = sock.accept()
	print("served")
	new_connection = Connection(conn, addr)
	new_connection.make_secure_connection_for_server()
	magic()
	
	threading.Thread(target=fucking_function_for_server).start()


def func(event):
	message = txt.get()
	if message != "":
		lbox.insert(END, 'You: ' + message)
		lbox.yview(END)
		txt.delete(0, END)
		if whoami:
			new_connection.send_message_for_server(message)
		else:
			new_connection.send_message_for_client(message)
	else:
		pass

def magic():
	global txt, lbox, btn, scrollbar
	scrollbar = Scrollbar(root)
	scrollbar.pack(side=RIGHT, fill=Y)
	txt = Entry(root, justify=LEFT, bg='#17212B', fg='#8ED4F2', bd=5, font=("Arial",16), selectbackground='green', selectforeground='blue') #'Write a message...')
	lbox = Listbox(font=("Calibri",20), bg='#0E1621', fg='#8ED4F2', selectbackground='#2E70A5', yscrollcommand=scrollbar.set, highlightthickness='0')
	btn = Button(root, text="Send", width=10, bg = '#6C7883',command=send)
	btn.pack(side='bottom', fill='x', ipady=6)
	txt.pack(side='bottom', fill='x', ipady=10)
	lbox.pack(side='top', expand=YES, fill='both')
	scrollbar.config(command=lbox.yview)

def create_client():
	global new_connection, port
	port = int(inputport.get())
	host = inputhost.get()
	
	check_tor()
	print(1)
	tor_activation(port)
	print(2)
	win2.destroy()

	new_connection = Connection(host, port)
	print(3)

	new_connection.make_secure_connection_for_client()

	magic()
	threading.Thread(target=fucking_function_for_client).start()

def plus_info():
	global inputhost, inputport, win2
	win.destroy()
	win2 = Toplevel(root, relief=SUNKEN, bd=10, bg="lightblue")
	inputport = Entry(win2)
	info_label_port = Label(win2, text="Port")

	if whoami:
		okay_for_start = Button(win2, text='Okay', command=create_server)
	else:
		info_label_host = Label(win2, text="Host")
		info_label_host.pack()
		inputhost = Entry(win2)
		inputhost.pack()
		okay_for_start = Button(win2, text='Okay', command=create_client)


	info_label_port.pack()
	inputport.pack()
	okay_for_start.pack()

def wait_change_client():
	global whoami
	whoami = False
	plus_info()


root.bind('<Return>', func)

root.title("Недочат")
root.geometry("1100x600")
root.config(bg="#0E1621")

win = Toplevel(root, relief=SUNKEN, bd=10, bg="lightblue")
win.title("Choose who are you")
win.minsize(width=300, height=150)
whois1 = Button(win, text='I wanna be a server', command=plus_info)
whois2 = Button(win, text='I wanna be a client', command=wait_change_client)

whois1.pack()
whois2.pack()


root.mainloop()



#https://www.torproject.org/dist/torbrowser/10.0.12/tor-win32-0.4.5.6.zip