#!/usr/bin/env python
# encoding: utf-8
"""
server.py
    Copyright (C) 2010  Skyler Leonard

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import sys, os, socket, shutil, bz2, time, getpass
from multiprocessing import Process
import xml.dom.minidom as dom


VERSION = 0.1

DATA_DIR = "data"

ENC = "UTF+8"

LOG = os.path.join(DATA_DIR, "server.log")

PORT = 37210

def get_values(text):
	"""get values from something sent"""
	text_list = text.split(":")
	key = text_list[1]
	values = text_list[2:]
	return (key, values)

def write_log(text, prnt=1):
	with open(LOG, "a") as log_file:
		log_file.write(text + "\n")
	if prnt > 0:
		print(text)
		
def safe_listdir(folder):
	return [f_name for f_name in os.listdir(folder) if f_name[0] != "."]

def serv_main(connection, address):
	"""Main handleing"""
	# Start with some handshakes / checking
	tries = 0
	while True:
		if tries > 1024:
			write_log("recv limit reached for address " + str(address) + ". Closing connection.")
			connection.close()
			return
		else:
			tries += 1
		v_res = connection.recv(1024)
		if not v_res[:9] == b":VERSION:":
			connection.send(b"!INVALID!")
			continue
		null, client_version = get_values(v_res.decode(ENC))
		client_version = float(client_version[0])
		if client_version < VERSION:
			connection.send(b"!UPDATE!")
			break
		else:
			connection.send(b"!NO_UPDATE!")
			break
	logged_in = None
	tries = 0
	while not logged_in:
		if tries > 1024:
			write_log("recv limit reached for address " + str(address) + ". Closing connection.")
			connection.close()
			return
		else:
			tries += 1
		l_res = connection.recv(1024)
		if not l_res == b"!LOGIN!":
			connection.send(b"!INVALID!")
			continue
		connection.send(b"?USER?")
		u_res = connection.recv(1024)
		if not u_res[:6] == b":USER:":
			connection.send(b"!INVALID!")
			continue
		null, users = get_values(u_res.decode())
		user = users[0]
		user_dir = os.path.join(DATA_DIR, "users", user)
		if not os.path.exists(user_dir):
			connection.send(b"!INVALID_USER!")
			continue
		connection.send(b"?PASSWORD?")
		p_res = connection.recv(1024)
		if not p_res[:10] == b":PASSWORD:":
			connection.send(b"!INVALID_PASSWORD!")
			continue
		bz_password = p_res[10:]
		password = bz2.decompress(bz_password)
		with open(os.path.join(user_dir, "password"), "rb") as p_file:
			if not password == p_file.read():
				connection.send(b"!INVALID_PASSWORD!")
				continue
			else:
				logged_in = True
		connection.send(b"!LOGGED_IN!")
	# set domain
	real_userdir = os.path.realpath(os.path.abspath(user_dir))
	domain = real_userdir.split("/")[-2]
	# clean up
	del v_res, l_res, u_res, p_res, logged_in
	tries = 0
	while True:
		"""Variables:
				user
				user_dir
				address, connection
				[res]
				"""
		null = None
		res = connection.recv(1024)
		if res: write_log(str(address) + " | " + str(user) + " | " + str(res))
		if res == b"!LOGOUT!":
			connection.close()
			return
		elif not res:
			tries += 1
			if tries > 1024:
				write_log("recv limit reached for user " + str(user) + ". Closing connection.")
				connection.close()
				return
		elif res[:5] == b"?LIST":
			# List options
			if res == b"?LIST_COMPUTER?":
				comp_dir = os.path.join(user_dir, "computers")
				comp_list = safe_listdir(comp_dir)
				sent_str = "\n".join(comp_list)
				sent_bytes = bytes(":LIST_COMPUTER:" + sent_str, ENC)
				sent = sent_bytes
				del comp_dir, comp_list, sent_str, sent_bytes
			elif res[:15] == b"?LIST_COMPUTER_":
				comp_name = res[15:-1].decode(ENC)
				comp_dir = os.path.join(user_dir, "computers")
				comp_path = os.path.join(comp_dir, comp_name)
				if not os.path.exists(comp_path):
					connection.send(b"!INVALID!")
					continue
				parts = safe_listdir(comp_path)
				sent_str = "\n".join(parts)
				sent_bytes = bytes(":LIST_COMPUTER_"+comp_name+":" + sent_str, ENC)
				sent = sent_bytes
				del comp_name, comp_dir, comp_path, parts, sent_str, sent_bytes
			elif res == b"?LIST_PART?":
				parts_dir = os.path.join(user_dir, "parts")
				parts_list = safe_listdir(parts_dir)
				sent_str = "\n".join(parts_list)
				sent_bytes = bytes(":LIST_PART:" + sent_str, ENC)
				sent = sent_bytes
				del parts_dir, parts_list, sent_str, sent_bytes
			elif res == b"?LIST_PROGRAM?":
				prog_dir = os.path.join(user_dir, "programs")
				prog_list = safe_listdir(prog_dir)
				sent_str = "\n".join(prog_list)
				sent_bytes = bytes(":LIST_PROGRAM:" + sent_str, ENC)
				sent = sent_bytes
				del prog_dir, prog_list, sent_str, sent_bytes
			else:
				comps = len(safe_listdir(os.path.join(user_dir, "computers")))
				parts = len(safe_listdir(os.path.join(user_dir, "parts")))
				progs = len(safe_listdir(os.path.join(user_dir, "programs")))
				sent_str = str(comps) + " computers\n" + str(parts) + " spare parts\n" + str(progs) + " programs\n"
				sent_bytes = bytes(":LIST:" + sent_str, ENC)
				sent = sent_bytes
				del comps, parts, progs, sent_str, sent_bytes
			connection.send(sent)
		elif res == b"!RENAME!":
			# rename computers
			connection.send(b"?ORIGINAL?")
			tries = 0
			r_res = connection.recv(1024)
			if not r_res[:10] == b":ORIGINAL:":
				connection.send(b"!INVALID!")
				continue
			null, original = get_values(r_res.decode(ENC))
			original = original[0]
			if not original in safe_listdir(os.path.join(user_dir, "computers")):
				connection.send(b"!INVALID!")
				continue
			connection.send(b"?NEW?")
			tries = 0
			r_res = connection.recv(1024)
			if not r_res[:5] == b":NEW:":
				connection.send(b"!INVALID!")
				continue
			null, new = get_values(r_res.decode(ENC))
			new = new[0]
			os.rename(os.path.join(user_dir, "computers", original), os.path.join(user_dir, "computers", new))
			connection.send(b"!RENAMED!")
			del r_res, original, new
		elif res == b"!NEW_COMPUTER!":
			# create a new computer
			created = None
			name_int = 0
			while not created:
				try:
					os.mkdir(os.path.join(user_dir, "computers", "computer" + str(name_int)))
					created = True
					break
				except OSError:
					name_int += 1
					continue
			connection.send(b"!CREATED!")
			del created, name_int
		elif res[:5] == b":ADD:":
			# add a part to computer
			res_list = res.split(b":")
			null, cmd, part, computer = res_list
			computer, part = computer.decode(ENC), part.decode(ENC)
			parts_dir = os.path.join(user_dir, "parts")
			comp_dir = os.path.join(user_dir, "computers")
			if not part in safe_listdir(parts_dir) or not computer in safe_listdir(comp_dir):
				connection.send(b"!INVALID!")
				continue
			os.rename(os.path.join(parts_dir, part), os.path.join(comp_dir, computer, part))
			connection.send(b"!ADDED!")
			del cmd, part, computer, res_list, parts_dir, comp_dir
		elif res[:8] == b":REMOVE:":
			res_list = res.split(b":")
			null, cmd, part, computer = res_list
			computer, part = computer.decode(ENC), part.decode(ENC)
			parts_dir = os.path.join(user_dir, "parts")
			comp_dir = os.path.join(user_dir, "computers")
			if not computer in safe_listdir(comp_dir) or not part in safe_listdir(os.path.join(comp_dir, computer)):
				connection.send(b"!INVALID!")
				continue
			print(comp_dir, computer, part, " || ", parts_dir, part)
			os.rename(os.path.join(comp_dir, computer, part), os.path.join(parts_dir, part))
			connection.send(b"!REMOVED!")
			del cmd, part, computer, res_list, parts_dir, comp_dir
		elif res[1:5] == b"MAIL":
			mail_dir = os.path.join(user_dir, "mail")
			messages = safe_listdir(mail_dir)
			unread, read = [[], []]
			for message in messages:
				if message[0] == "*":
					unread.append(message)
				else:
					read.append(message)
			if res == b"?MAIL?":
				bstr_unread = bytes(str(len(unread)), ENC)
				bstr_read = bytes(str(len(read)), ENC)
				connection.send(b":MAIL:"+bstr_unread+b":"+bstr_read)
			elif res == b"?MAIL_UNREAD?":
				unread_str = ":".join(unread)
				unread_bstr = bytes(unread_str, ENC)
				connection.send(b":MAIL_UNREAD:"+unread_bstr)
			elif res == b"?MAIL_READ?":
				read_str = ":".join(read)
				read_bstr = bytes(read_str, ENC)
				connection.send(b":MAIL_READ:"+read_bstr)
			elif res[:14] == b"?MAIL_MESSAGE_":
				b_message_id = res[14:-1]
				message_id = b_message_id.decode(ENC)
				if "*" + message_id in unread:
					with open(os.path.join(mail_dir, "*" + message_id), "rb") as msg_open:
						connection.send(b":MAIL_MESSAGE_" + b_message_id + b":" + bz2.compress(msg_open.read()))
					os.rename(os.path.join(mail_dir, "*" + message_id), os.path.join(mail_dir, message_id))
				elif message_id in read:
					with open(os.path.join(mail_dir, message_id), "rb") as msg_open:
						connection.send(b":MAIL_MESSAGE_" + b_message_id + b":" + bz2.compress(msg_open.read()))
				else:
					connection.send(b"!INVLAID!")
			elif res == b"!MAIL_SEND!":
				connection.send(b"?TO?")
				key, to = get_values(connection.recv(1024).decode(ENC))
				if not key == "TO":
					connection.send(b"!INVALID!")
					continue
				to_name, to_domain = to[0].split("@")
				if not os.path.exists(os.path.join(DATA_DIR, "users", to_domain, to_name)):
					connection.send(b"!INVALID!")
					continue
				connection.send(b"?SUBJECT?")
				key, subject = get_values(connection.recv(1024).decode(ENC))
				if not key == "SUBJECT":
					connection.send(b"!INVALID!")
					continue
				connection.send(b"?MESSAGE?")
				key, msg_text = get_values(connection.recv(1024).decode(ENC))
				if not key == "MESSAGE":
					connection.send(b"!INVALID!")
					continue
				time_stamp = "*" + str(int(time.time()*100))[-6:]
				message_text = "From: " + user + "@" + domain + "\nTO: " + to[0] + "\nSUBJECT: " + subject[0] + "\nMESSAGE:\n\t" + msg_text[0]
				message_file = os.path.join(DATA_DIR, "users", to_domain, to_name, "mail", time_stamp)
				with open(message_file, "w") as message_file_open:
					message_file_open.write(message_text)
				connection.send(b"!SENT!")
		elif res == "hi":
			pass
		else:
			connection.send(b"!UNKNOWN!")
		del null

def main():
	if not os.path.exists(DATA_DIR):
		print("Data directory not found. exit.")
		sys.exit(1)
	try:
		if sys.argv[1] == "new":
			name = sys.argv[2]
			domain = "newbie.net"
			users_dir = os.path.join(DATA_DIR, "users", domain)
			user = os.path.join(users_dir, name)
			template = os.path.join(DATA_DIR, "resource", "new.user")
			shutil.copytree(template, user, symlinks=True)
			os.symlink(os.path.abspath(user), os.path.join(DATA_DIR, "users", name))
			welcome = os.path.join(DATA_DIR, "resource", "welcome.msg")
			with open(welcome, "r") as welcome_open:
				welcome_text = welcome_open.read()
			welcome_text_mod = welcome_text.replace("#USER#", name).replace("#DOMAIN#", domain)
			user_welcome = os.path.join(user, "mail", "*" + str(int(time.time()*100))[-6:])
			with open(user_welcome, "w") as user_welcome_open:
				user_welcome_open.write(welcome_text_mod)
			print("User created")
			return
		elif sys.argv[1] == "suspend":
			raise NotImplementedError
			user_name = sys.argv[2]
			users_dir = os.path.join(DATA_DIR, "users")
			user = os.path.join(users_dir, user_name)
			users_sus = os.path.join(DATA_DIR, "users.suspended")
			shutil.move(user, os.path.join(users_sus, user_name))
			print("User suspended")
			return
		elif sys.argv[1] == "unsuspend":
			raise NotImplementedError
			user_name = sys.argv[2]
			users_dir = os.path.join(DATA_DIR, "users")
			user = os.path.join(users_dir, user_name)
			users_sus = os.path.join(DATA_DIR, "users.suspended")
			shutil.move(os.path.join(users_sus, user_name), user)
			print("User unsuspended")
			return
		elif sys.argv[1] == "password":
			name = sys.argv[2]
			users_dir = os.path.join(DATA_DIR, "users")
			user_dir = os.path.abspath(os.path.join(users_dir, name))
			user_dir = os.path.realpath(user_dir)
			password_file = os.path.join(user_dir, "password")
			with open(password_file, "w") as password_open:
				password_open.write(getpass.getpass())
			print("Password changed.")
			return
		elif sys.argv[1] == "domain":
			name = sys.argv[2]
			new_domain = input("New Domain: ")
			user = os.path.join(DATA_DIR, "users", name)
			user_real = os.readlink(os.path.abspath(user))
			new_path = os.path.abspath(os.path.join(DATA_DIR, "users", new_domain, name))
			os.renames(user_real, new_path)
			os.remove(user)
			os.symlink(new_path, os.path.abspath(user))
			return
		else:
			print("Unkown command. exit.")
			return
	except IndexError:
		pass
	try:
		HOST = None
		s = None
		for res in socket.getaddrinfo(HOST, PORT, socket.AF_UNSPEC,
									  socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
			af, socktype, proto, canonname, sa = res
			try:
				s = socket.socket(af, socktype, proto)
			except socket.error as msg:
				s = None
				continue
			try:
				s.bind(sa)
				s.listen(1)
			except socket.error as msg:
				s.close()
				s = None
				continue
			break
		if s is None:
			print('could not open socket')
			sys.exit(1)
		print("Server Started.")
		connected = {}
		while True:
			conn, addr = s.accept()
			print('Connected by', addr)
			Process(target=serv_main, args=(conn, addr)).start()
	except KeyboardInterrupt:
		s.close()


if __name__ == '__main__':
	main()

