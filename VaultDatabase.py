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

SQL_INSERT = "INSERT INTO {table:s}({columns:s}) VALUES({values:s})"
SQL_NEW_ARCHIVE_VALUES = "'{filename:s}','{password:s}'"
SQL_NEW_FILE_VALUES = "'{filename:s}','{md5:s}','{sha1:s}'"
#//////////////////////////////////////////////////////////
# Classes
class VaultDatabase(object):

	DEFAULT_VAULT_DB_FILE	=	"vxvault.db"

	DefaultSchemaFile = "./db/schema-1.0.sql"

	def __init__(self, _file, _schema=DefaultSchemaFile, _logger=None):
		# Creates a new logger object.
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		
		self.set_db_file(_file)
		self.db_schema_file = _schema
		
	def create_database(self, _overwrite=False):
		#**********************************************************************
		# Verify if the sqllite file has been set
		# if not, exit.
		#**********************************************************************
		if (len(self.db_file) <= 0):
			raise Exception("No file specified for database.")

		#**********************************************************************
		# Check if a valid database schema is provided.
		#**********************************************************************
		if (len(self.db_schema_file) <= 0 
			or not os.path.isfile(self.db_schema_file)):
			raise Exception("No database schema found.")
		#**********************************************************************
		# Check if the file exist and we're allowed
		# to overwrite, otherwise, raise exception.
		#**********************************************************************
		if (not _overwrite and self.db_file_exists()):
			raise Exception(ERR_DB_FILE_EXIST)
		elif (_overwrite and self.db_file_exists()):
			os.remove(self.db_file)

		#**********************************************************************
		# Opens the schema definition of the vault 
		# database.
		#**********************************************************************
		with open(self.db_schema_file, "r") as f:
			sql = f.read();
		
		#**********************************************************************
		# Checks content was read from the file.
		#**********************************************************************
		if not(sql and len(sql) > 0):
			raise Exception("Database schema file is empty.")
		
		#**********************************************************************
		# Open the sqlite database file and execute the SQL 
		# contents read from the schema.
		#**********************************************************************
		db_conn = sqlite3.connect(self.db_file)
		db_conn.executescript(sql)
		
		self.logger.print_success("Loaded database '{:s}' successfully.".format(self.db_file))	
		
	def set_db_file(self, _file):
		if not _file:
			raise Exception(ERR_NULL_OR_EMPTY.format(u'file'))
			
		self.db_file = _file
		
	def get_db_file(self):
		return self.db_file
		
	def db_file_exists(self):
		return os.path.isfile(self.db_file)
		
	def add_archive(self, _vx):
		if (_vx):
			vx_archive = _vx.get_archive()
			vx_password = _vx.get_password()
			
			self.logger.print_debug("Adding '{:s}' to database.".format(vx_archive))
			new_id = self._new_archive_record(vx_archive, vx_password)
			self.logger.print_debug("Archive '{:s}' successfully added with id '{:d}'.".format(vx_archive, new_id))
			
			vx_files = _vx.get_files()
			for vx_file in vx_files:
				#
				# TODO:
				# [ ] Support multiple file malware
				vx_file_md5 = _vx.md5()
				vx_file_sha1 = _vx.sha1()
				new_id = self._new_file(vx_file, vx_file_md5, vx_file_sha1)
				self.logger.print_debug("\tAdding file '{:s}' to database.".format(vx_file))
			#
			# TODO:
			# Incomplete.
		else:
			raise Exception("Virus object cannot be null.")
		
	def _new_archive_record(self, _archive, _password):
		if (not _archive and len(_archive) < 0):
			raise Exception("Archive name cannot be null or empty.")
		
		archive_values = SQL_NEW_ARCHIVE_VALUES.format(
			filename=_archive, 
			password=_password)
		sql_new_archive = SQL_INSERT.format(
			table="Archives", 
			columns="filename, password", 
			values=archive_values)
		new_id = self._execute_sql(sql_new_archive)
		return new_id
		
	def _new_file(self, archive_id, _filename, _md5, _sha1):
		file_values = SQL_NEW_FILE_VALUES.format(
			filename=_filename,
			md5=_md5,
			sha1=_sha1
		)
		sql_new_file = SQL.INSERT.format(
			table="Files",
			columns="filename, md5, sha1",
			values=file_values
		)
		new_id = self._execute_sql(sql_new_file)
		return new_id
		
	def _execute_sql(self, _sql):
		last_id = -1
		if (len(_sql) > 0):
			db_conn = sqlite3.connect(self.db_file)
			db_cursor = db_conn.cursor()
			self.logger.print_debug(_sql)
			db_cursor.execute(_sql)
			last_id = db_cursor.lastrowid
		return last_id
		
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
		