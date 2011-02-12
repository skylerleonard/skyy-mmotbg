#!/usr/bin/env python
# encoding: utf-8
"""
	main.py
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

import sys, os, getopt, socket, getpass, bz2, shlex

# Server Name:
SERVER = '127.0.0.1'

# Encoding for transfers
ENC = 'UTF+8'

# Mute non-vital messages.
MUTE = "-m" in sys.argv[1:]

VERSION = "0.1"

PORT = 37210

# -------------------------------------------

def p_input(prompt):
	"""a controlled input"""
	try:
		response = input(prompt)
		if not response:
			response = "null"
	except (EOFError, KeyboardInterrupt):
		sys.stdin.flush()
		response = 'exit'
		print("exit")
	return response

def p_print(text, p_type=0):
	"""a controlled output"""
	if isinstance(text, bytes):
		text = text.decode(ENC)
	if p_type == 0:
		if not MUTE: print(text)
	elif p_type == 1:
		print(text)
	elif p_type == 2:
		print("ERROR: "+text)

# Shorthand to open a socket.
def open_socket(HOST):
	"""open the socket"""
	s = None
	for res in socket.getaddrinfo(HOST, PORT, socket.AF_UNSPEC, socket.SOCK_STREAM):
	    af, socktype, proto, canonname, sa = res
	    try:
	        s = socket.socket(af, socktype, proto)
	    except socket.error as msg:
	        s = None
	        continue
	    try:
	        s.connect(sa)
	    except socket.error as msg:
	        s.close()
	        s = None
	        continue
	    break
	return s

class Server_Talk():
	"""Some Functions to communicate with the server"""
	def __init__(self, conn):
		self.conn = conn
		self.error = "Could not complete operation."
	def expects(self, text, expects, error=None):
		"""Send some text, and expect a cirtain response"""
		if error is None: error = self.error
		if not isinstance(text, bytes):
			text = bytes(text, ENC)
		if not isinstance(expects, bytes):
			expects = bytes(expects, ENC)
		self.conn.send(text)
		res = None
		while not res:
			res = self.conn.recv(1024)
		if not res == expects:
			p_print(error + " Trying again.")
			self.conn.send(text)
			res = None
			while not res:
				res = self.conn.recv(1024)
			if not res == expects:
				p_print(error, 2)
				return None
		self.error = error
		return True
	def ask(self, text, error=None):
		"""Ask for a value"""
		if error is None: error = self.error
		if not isinstance(text, bytes):
			text = bytes(text, ENC)
		ques = b"?"+text+b"?"
		r_head = b":"+text+b":"
		h_len = len(r_head)
		self.conn.send(ques)
		res = None
		while not res:
			res = self.conn.recv(1024)
		if not res[:h_len] == r_head:
			p_print(error + " Trying again.")
			self.conn.send(ques)
			res = None
			while not res:
				res = self.conn.recv(1024)
			if not res[:h_len] == r_head:
				p_print(error, 2)
				return None
		self.error = error
		return res[h_len:]

# The Commands
class Commands():
	def __init__(self, connection):
		self.conn = connection
		self.talk = Server_Talk(connection)
	def list(self, cmd, hide=0):
		"""List your computers"""
		try:
			if cmd[1] in ["computers", "computer"]:
				try:
					name = "_" + cmd[2]
				except IndexError:
					name = ""
				question = "LIST_COMPUTER" + name
			elif cmd[1] in ["parts"]:
				question = "LIST_PART"
			elif cmd[1] in ["programs"]:
				question = "LIST_PROGRAM"
			else:
				question = "LIST"
		except IndexError:
			question = "LIST"
		the_list = self.talk.ask(question, error="Could not recieve list.")
		if not the_list is None and hide == 0: p_print(the_list, 1)
	def enter(self, cmd):
		"""Enter into a computer"""
		try:
			comp = cmd[1]
			if not comp in self.list(["list", "computers"]):
				p_print("Computer does not exist.", 2)
				return
		except IndexError:
			p_print("Please specify a computer to login to.", 2)
			return
		return prompt_computer(self, self.conn, self.talk, comp)
	def edit(self, cmd):
		"""Edit computer configurations"""
		return prompt_edit(self, self.conn, self.talk)
	def mail(self, cmd):
		"""Check Email"""
		return prompt_mail(self, self.conn, self.talk)

# Functions for the various prompts
def prompt_login():
	"""login etc."""
	user_name = input("Login: ")
	user_password = getpass.getpass()
	return (user_name, user_password)

def prompt_main(connection):
	"""The main prompt, where most things happen"""
	comm = Commands(connection)
	while True:
		cmd = p_input("do: ")
		if cmd in ["exit", "logout"]:
			return cmd
		else:
			cmd_split = shlex.split(cmd)
			cmd_name = cmd_split[0]
			if cmd_name in ["list", "ls"]:
				comm.list(cmd_split)
			elif cmd_name in ["rename"]:
				comm.rename(cmd_split)
			elif cmd_name in ["login", "enter"]:
				comm.enter(cmd_split)
			elif cmd_name in ["edit"]:
				comm.edit(cmd_split)
			elif cmd_name in ["mail", "email"]:
				comm.mail(cmd_split)

def prompt_edit(commands, connection, talk):
	"""Edit computer configurations"""
	while True:
		edit_cmd = p_input("edit: ")
		edit_cmd = shlex.split(edit_cmd)
		if edit_cmd[0] in ["exit"]:
			return
		elif edit_cmd[0] in ["list", "ls"]:
			commands.list(edit_cmd)
		elif edit_cmd[0] in ["new"]:
			talk.expects("!NEW_COMPUTER!", "!CREATED!", error="Could not create new computer.")
		elif edit_cmd[0] in ["add", "install"]:
			part = edit_cmd[1]
			computer = edit_cmd[2 + (edit_cmd[2] in ["to"])]
			sent = ":ADD:" + part + ":" + computer
			talk.expects(sent, "!ADDED!", error="Could not add part to computer.")
		elif edit_cmd[0] in ["remove", "uninstall"]:
			part = edit_cmd[1]
			computer = edit_cmd[2 + (edit_cmd[2] in ["from"])]
			sent = ":REMOVE:" + part + ":" + computer
			talk.expects(sent, "!REMOVED!", error="Could not remove part from computer.")
		elif edit_cmd[0] in ["rename"]:
			try:
				orig = edit_cmd[1]
				new = edit_cmd[2]
			except IndexError:
				p_print("Please specify both a original name and a new name.", 2)
				continue
			# Tell the server we want to rename
			try_init = talk.expects("!RENAME!", "?ORIGINAL?", error="Could not rename.")
			if try_init is None:
				return
			# Tell the server the original name
			try_orig = talk.expects(":ORIGINAL:"+orig, "?NEW?", error="Could not rename.")
			if try_orig is None:
				return
			# Tell the server the new name
			try_new = talk.expects(":NEW:"+new, "!RENAMED!", error="Could not rename.")
			if try_new is None:
				return
			p_print("Done.", 1)
		
def prompt_computer(commands, connection, talk, computer):
	"""enter a computer"""
	return
	while True:
		pass
		
def prompt_mail(commands, connection, talk):
	"""Check Email"""
	inbox_b = talk.ask("MAIL", error="Could not open inbox.")
	if inbox_b is None:
		return
	inbox = inbox_b.decode(ENC)
	unread_count, read_count = inbox.split(":")
	p_print(unread_count+" new messages. "+read_count+" read messages.", 1)
	while True:
		mail_cmd = p_input("mail: ")
		mail_cmd = shlex.split(mail_cmd)
		if mail_cmd[0] in ["exit"]:
			return
		elif mail_cmd[0] in ["unread", "check"]:
			messages = talk.ask("MAIL_UNREAD")
			messages = "\n".join(messages.decode(ENC).split(":"))
			if messages: p_print(messages, 1)
		elif mail_cmd[0] in ["read", "old"]:
			messages = talk.ask("MAIL_READ")
			if messages: p_print(messages, 1)
		elif mail_cmd[0] in ["open"]:
			message_id = mail_cmd[1]
			message_bzip = talk.ask("MAIL_MESSAGE_"+message_id, error="Could not open message.")
			p_print("", 1)
			p_print(bz2.decompress(message_bzip), 1)
			p_print("", 1)
		elif mail_cmd[0] in ["send"]:
			if talk.expects("!MAIL_SEND!", expects="?TO?", error="Could not send message.") is None:
				continue
			to = p_input("TO: ")
			if talk.expects(":TO:"+to, expects="?SUBJECT?") is None:
				continue
			subject = p_input("SUBJECT: ")
			if talk.expects(":SUBJECT:"+subject, expects="?MESSAGE?") is None:
				continue
			message_text = p_input("MESSAGE: ")
			if talk.expects(":MESSAGE:"+message_text, expects="!SENT!") is None:
				continue
			

def main():
	while True:
		#
		# Try to connect to the server.
		#
		connection = open_socket(SERVER)
		if connection is None:
			p_print("could not connect.", 2)
			return 1
		#
		# Check for updates...
		#
		version = b":VERSION:"+bytes(VERSION, ENC)
		connection.send(version)
		res_version = None
		while not res_version:
			res_version = connection.recv(1024)
		if res_version == b"!UPDATE!":
			p_print("A new version is avalible.", 1)
		#
		# Try to login.
		#
		logged_in = None
		while not logged_in:
			connection.send(b"!LOGIN!")
			l_resp = None
			while not l_resp:
				l_resp = connection.recv(1024)
			if not l_resp == b"?USER?":
				p_print("There was a problem requesting a login. Trying again.")
				continue
			user, passwd = prompt_login()
			
			connection.send(b":USER:"+bytes(user, ENC))
			u_resp = None
			p_resp = None
			while not u_resp:
				u_resp = connection.recv(1024)
			if u_resp == b"!INVALID_USER!":
				p_print("Incorrect Username", 2)
				continue
			elif u_resp == b"?PASSWORD?":
				# Well, at least were not sending the password blatently over the network...
				bz_passwd = bz2.compress(bytes(passwd, ENC))
				connection.send(b":PASSWORD:"+bz_passwd)
				while not p_resp:
					p_resp = connection.recv(1024)
					if p_resp == b"!INVALID_PASSWORD!":
						p_print("Incorrect Password", 2)
						continue
					elif p_resp == b"!LOGGED_IN!":
						logged_in = True
					else:
						p_print("Strange data from server. Try again.", 2)
						continue
			else:
				p_print("Strange data from server. Try again.", 2)
				continue
		p_print("Login success!", 1)
		done = prompt_main(connection)
		if done == "logout":
			connection.send(b"!LOGOUT!")
			continue
		elif done == "exit":
			connection.send(b"!LOGOUT!")
			return 0
		else:
			connection.send(b"!LOGOUT!")
			return done

if __name__ == '__main__':
	sys.exit(main())

