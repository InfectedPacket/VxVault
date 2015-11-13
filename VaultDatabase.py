#!/usr/bin/env python
# -*- coding: latin-1 -*-
#█▀▀▀▀█▀▀▀▀▀██▀▀▀▀██▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀▀▓▒▀▀▀▀▀▀▀▀▀▀█▓▀ ▀▀▀██▀▀▀▀▀▀▀▀▀▓▓▀▀▀▀▀▀▀▀▀▌
#▌▄██▌ ▄▓██▄ ▀▄█▓▄▐ ▄▓█▓▓▀█ ▄▓██▀▓██▓▄ ▌▄█▓█▀███▓▄ ▌▄█▓█ ▀ ▄▓██▀▓██▓▄ ▄█▓█▀███▄■
#▌▀▓█▓▐▓██▓▓█ ▐▓█▓▌▐▓███▌■ ▒▓██▌ ▓██▓▌▐▓▒█▌▄ ▓██▓▌ ▐▓▒█▌▐ ▒▓██▌  ▓██▓▌▓▒█▌ ▓█▓▌
#▐▓▄▄▌░▓▓█▓▐▓▌ █▓▓▌░▓▓█▓▄▄ ▓▓██▓▄▄▓█▓▓▌░▓█▓ █ ▓█▓▓▌░▓█▓ ▒ ▓▓██▓▄▄▓█▓▓▌▓█▓ ░ ▓█▓▓
#▐▓▓█▌▓▓▓█▌ █▓▐██▓▌▐▓▒▓▌ ▄ ▐░▓█▌▄ ▀▀▀ ▐▓▓▓ ▐▌ ▀▀▀  ▐▓▓▓▄▄ ▐░▓█▌ ▄ ▀▀▀ ▓▓▓ ░ ██▓▓
#▐▓▓▓█▐▓▒██ ██▓▓▓▌▐▓▓██  █▌▐▓▓▒▌▐ ███░▌▐▓▓▒▌▐ ███░▌ ▐▓▓▒▌ ▐▓▓▒▌▀ ███░▌▓▓▒▌ ███░
# ▒▓▓█▌▒▓▓█▌ ▐▓█▒▒  ▒▓██▌▐█ ▒▓▓█ ▐█▓▒▒ ▒▒▓█  ▐█▓▒▒  ▒▒▓█ ▓▌▒▓▓█ ▐█▓▒▒ ▒▒▓█ ▐█▓▒▌
#▌ ▒▒░▀ ▓▒▓▀  ▀░▒▓ ▐▌ ▓▓▓▀ █ █▒▓▀▀░█▓ ▄▌ ▒▒▓▀▀░█▓ ▄▌ ▒▒▓▀▀ █▒▓▀▀░█▓ ▒▒▓▀▀░█▀
#█▄ ▀ ▄▄ ▀▄▄▀■ ▀ ▀▓█▄ ▀ ▄█▓█▄ ▀ ▓▄▄▄▄▄█▀ ▄▀ ▄▄▄▄▄▄█▓▄ ▀ ▄▄█▓▄▀ ▄▓▄█▄▀ ▄▄▄█▌
#
# Copyright (C) 2015 Jonathan Racicot
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http:#www.gnu.org/licenses/>.
# </copyright>
# <author>Jonathan Racicot</author>
# <email>infectedpacket@gmail.com</email>
# <date>2015-10-25</date>
# <url>https://github.com/infectedpacket</url>

#//////////////////////////////////////////////////////////
# Imports Statements
import os
import sys
import sqlite3
import os.path

from Virus import Virus
from Logger import Logger
#//////////////////////////////////////////////////////////
# Constants
ERR_NULL_OR_EMPTY	=	"Value for variable '{:s}' cannot be null or empty."
ERR_DB_FILE_EXIST	=	"Vault database already exists in folder."
#//////////////////////////////////////////////////////////
# Classes
class VaultDatabase(object):

	DEFAULT_VAULT_DB_FILE	=	".vxvault.db"

	TBL_VX		=	"vx"

	def __init__(self, _file=VaultDatabase.DEFAULT_VAULT_DB_FILE, _logger=None):
		if _logger = None: self.logger = Logger(sys.stdout)
		self.db_file = _file
		
	def set_db_file(self, _file):
		if not _file:
			raise Exception(ERR_NULL_OR_EMPTY.format(u'file'))
			
		self.db_file = _file
		
	def get_db_file(self):
		return self.db_file

	def create_db_file(self, _overwrite=False):
		if not self.db_file:
			raise Exception(ERR_NULL_OR_EMPTY.format(u'db_file'))	
	
		if (self.db_file_exists() and _overwrite):
			os.remove(self.db_file)
		elif (self.db_file_exist() and not _overwrite):
			raise Exception(ERR_DB_FILE_EXIST)
			
		#Creates the file
		open(self.db_file, 'w').close()
		
		db_conn = sqlite3.connect(self.db_file)
		db_cursor = db_conn.cursor()
		
		db_conn.close()
		
	def db_file_exists(self):
		return os.path.isfile(self.db_file)
		
	def create_vx(self, _vx):
		print("not implemented")
		
	def read_vx_by_md5(self, _md5):
		print("not implemented")
	
	def read_vx_by_file(self, _md5):
			print("not implemented")
	
	def update_vx(self, _vx):
		print("not implemented")
		
	def delete_vx(self, _vx):
		print("not implemented")
		
	def vx_exists(self, _vx):
		print("not implemented")
		