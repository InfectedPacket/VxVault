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

from Virus import Virus, VirusFile
from Logger import Logger
from VaultExceptions import *
#//////////////////////////////////////////////////////////
# Constants
ERR_NO_ARCHIVE_NAME = "No archive name has been defined for Virus object."
ERR_DB_SCHEMA_EMPTY = "Database schema file is empty."

TBL_FILES = "Files"
COL_FILES = "filename, md5, sha1, sha256, archive_id"

SQL_INSERT = "INSERT INTO {table:s}({columns:s}) VALUES({values:s})"
SQL_NEW_ARCHIVE_VALUES = "'{filename:s}', '{path:s}', '{hash:s}', '{password:s}'"
SQL_NEW_FILE_VALUES = "'{filename:s}','{md5:s}','{sha1:s}','{sha256:s}',{archive:d}"
SQL_SELECT_FILE_BY_SHA = "SELECT * FROM Files WHERE sha1 ='{:s}'"
#//////////////////////////////////////////////////////////
# Classes
class VaultDatabase(object):

	DEFAULT_VAULT_DB_FILE	=	".vxvault.db"

	DefaultSchemaFile = "./schema-1.0.sql"

	def __init__(self, _file, _schema=DefaultSchemaFile, _logger=None):
		#**********************************************************************
		# Creates a new logger object.
		#**********************************************************************
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		
		#**********************************************************************
		# Specifies the sqlite database file.
		#**********************************************************************
		self.set_db_file(_file)
		#**********************************************************************
		# Specifies the SQL database schema file.
		#**********************************************************************
		self.db_schema_file = _schema
		
	def create_database(self, _overwrite=False):
		""" Creates the database from the SQL schema provided to the
		VaultDatabase.
		
		This functions creates the database or overwrite the database
		file if the _overwrite argument is set to True. 
		
		Args:
			_overwrite; Recreates the database schema if it already
			exists.
			
		Returns:
			None.
			
		Raises:
			Exception if database file already exists and _overwrite is
			set to False. Raises an exception if the database schema file
			is not found or the file is empty. Raises an exception if
			there is a SQL error while creating the schema.
		
		"""
		#**********************************************************************
		# Verify if the sqllite file has been set
		# if not, exit.
		#**********************************************************************
		if (len(self.db_file) <= 0):
			raise NoDatabaseFileSpecifiedException()

		#**********************************************************************
		# Check if a valid database schema is provided.
		#**********************************************************************
		if (len(self.db_schema_file) <= 0 
			or not os.path.isfile(self.db_schema_file)):
			raise FileNotFoundException(self.db_schema_file)
		#**********************************************************************
		# Check if the file exist and we're allowed
		# to overwrite, otherwise, raise exception.
		#**********************************************************************
		if (not _overwrite and self.db_file_exists()):
			raise DatabaseFileExistsException()
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
			raise Exception(ERR_DB_SCHEMA_EMPTY)
		
		#**********************************************************************
		# Open the sqlite database file and execute the SQL 
		# contents read from the schema.
		#**********************************************************************
		db_conn = sqlite3.connect(self.db_file)
		db_conn.executescript(sql)
		
		self.logger.print_success(INFO_DB_LOADED.format(self.db_file))	
		
	def set_db_file(self, _file):
		""" Specifies which file contains the sqlite databse. 
		
		This functions sets the file in which the sqlite database
		will be stored. 
		
		Args:
			_file : Absolute path to the file containing the database.
			
		Returns:
			None.
			
		Raises:
			Exception if the provided argument is null or empty.
		"""
		
		if not _file:
			raise NullOrEmptyArgumentException()
			
		self.db_file = _file
		
	def get_db_file(self):
		return self.db_file
		
	def db_file_exists(self):
		return os.path.isfile(self.db_file)
		
	def add_malware(self, _vx):
		#**********************************************************************
		# Verfies Virus object is not null.
		#**********************************************************************
		if (_vx):
			vx_archive = _vx.get_archive()
			vx_archive_name = os.path.basename(vx_archive)
			vx_path = os.path.dirname(vx_archive)
			#**********************************************************************
			# Verify if an archive name has been generated
			# for the virus object. Abort if not.
			#**********************************************************************
			if (vx_archive and len(vx_archive) > 0):
				vx_password = _vx.get_password()
				
				#
				# Adds new "Archive" row to the database.
				#
				vx_sha1 = _vx.get_archive_sha1()
				new_id = self._new_archive_record(vx_archive_name, vx_path, vx_sha1, vx_password)
				self.logger.print_success(INFO_DB_ARCHIVE_ADDED.format(vx_archive, new_id))
				
				#
				# For each file composing the malware, add a Files
				# row to the database.
				#
				vx_files = _vx.get_files()
				for vx_file in vx_files:
					vx_file_name = vx_file.get_file()
					vx_file_md5 = vx_file.get_md5()
					vx_file_sha1 = vx_file.get_sha1()
					vx_file_sha256 = vx_file.get_sha256()
					new_id = self._new_file(new_id, vx_file_name, vx_file_md5, vx_file_sha1, vx_file_sha256)
					self.logger.print_debug(INFO_DB_FILE_ADDED.format(vx_file))

					#
					# Save the idents found for each file.
					#
					vx_idents = vx_file.get_antiviral_results()
					for (vx_av, vx_ident) in vx_idents.iteritems():
						self._new_ident(new_id, vx_av, vx_ident)
						self.logger.print_debug(INFO_DB_IDENT_ADDED.format(vx_av, vx_ident))

			else:
				raise NoArchiveException()
		else:
			raise NullOrEmptyArgumentException()
			
	def file_exists(self, _file):
		""" Verifies if the specified file is already recorded into the
		vault database.

		This function will calculate the SHA1 hash of the given file and verify
		if there is a matching entry in the Files table of the database.
		
		Args:
			_file: Absolute path of the file to verify.
			
		Returns:
			True if the SHA1 hash of the given file is found in the Files table
			of the database. False otherwise.
			
		Raises:
			Exception if null or empty arguments. Raise exception if given
			file is not found.
		"""
		if (_file and len(_file) > 0):
			if (os.path.exists(_file)):
				vx = VirusFile(_file)
				vx_sha1 = vx.get_sha1()
				sql = SQL_SELECT_FILE_BY_SHA.format(vx_sha1)
				result = self._exec_sql_select(sql)
				return len(result) > 0
			else:
				raise FileNotFoundException(_file)
		else:
			raise NullOrEmptyArgumentException()
	
	def _new_archive_record(self, _archive, _path, _hash, _password):
		""" Creates a new archive record in the database.
		
		This function will create a SQL query to add a new row into
		the Archives table within the vault database. 
		
		Args:
			_archive: Filename of the archive
			_password: Password needed to extract files from the
			archive.
		Returns:
			The archive_id of the newly created row.
			
		Raises:
			Exception if argument provided is null or empty. Raises
			exception from sqlite module on error.
		"""
		if (not _archive and len(_archive) < 0):
			raise NullOrEmptyArgumentException()
		
		#**********************************************************************
		# Formats the values needed to create a new archive
		# record.
		#**********************************************************************
		archive_values = SQL_NEW_ARCHIVE_VALUES.format(
			filename=_archive, 
			path=_path,
			hash=_hash,
			password=_password)
			
		#**********************************************************************
		# Creates the new INSERT sql statement.
		#**********************************************************************
		sql_new_archive = SQL_INSERT.format(
			table="Archives", 
			columns="filename, path, hash, password", 
			values=archive_values)
		
		#**********************************************************************
		# Returns the auto generated ID of the newly inserted
		# record.
		#**********************************************************************
		new_id = self._execute_sql(sql_new_archive)
		return new_id
		
	def _new_file(self, _archive_id, _filename, _md5, _sha1, _sha256):
		""" Inserts a new file record into the vault database.
		
		This function adds a new file record into the vault database.
		
		Args:
			_archive_id: The Archive ID which the file is included in.
			_filename: The name of the file.
			_md5: The MD5 hash, in hex format, of the file.
			_sha1: The SHA1 hash, in hex format, of the file.
			
		Returns:
			The new auto-generated ID of the new record.
			
		Raises:
			Exception from database connector.
		"""
		file_values = SQL_NEW_FILE_VALUES.format(
			filename=_filename,
			md5=_md5,
			sha1=_sha1,
			sha256 = _sha256,
			archive=_archive_id
		)
		
		#**********************************************************************
		# Creates the new INSERT sql statement.
		#**********************************************************************
		sql_new_file = SQL_INSERT.format(
			table=TBL_FILES,
			columns=COL_FILES,
			values=file_values
		)
		
		#**********************************************************************
		# Returns the auto generated ID of the newly inserted
		# record.
		#**********************************************************************
		new_id = self._execute_sql(sql_new_file)
		return new_id
		
	def _new_ident(self, _file_id, _av, _ident):
		SQL_NEW_IDENT = "{fileid:d},{avid:d},'{ident:s}'"
		av_id = self.get_av_id(_av)
		if (av_id and av_id > 0):
			ident_values = SQL_NEW_IDENT.format(fileid=_file_id, avid=av_id, 
				ident=_ident)
			sql_new_ident = SQL_INSERT.format(
				table="Idents",
				columns="file_id, av_id, name",
				values=ident_values
			)
			self._execute_sql(sql_new_ident)
		else:
			raise Exception("Failed to find AV id for '{:s}'.".format(_av))
		
	def get_av_id(self, _av):
		av_id = -1
		SQL_SELECT_AVID = "SELECT av_id FROM AVs WHERE name = '{:s}'"
		sql = SQL_SELECT_AVID.format(_av)
		db_conn = sqlite3.connect(self.db_file)
		db_cursor = db_conn.cursor()
		db_cursor.execute(sql)
		row = db_cursor.fetchone()
		if (row):
			av_id = row[0]
		return av_id

	def _execute_sql(self, _sql):
		last_id = -1
		if (len(_sql) > 0):
			db_conn = sqlite3.connect(self.db_file)
			db_cursor = db_conn.cursor()
			#self.logger.print_debug(_sql)
			db_cursor.execute(_sql)
			last_id = db_cursor.lastrowid
			db_conn.commit()
		return last_id

	def _exec_sql_select(self, _sql):
		if (len(_sql) > 0):
			db_conn = sqlite3.connect(self.db_file)
			db_cursor = db_conn.cursor()
			#self.logger.print_debug(_sql)
			db_cursor.execute(_sql)
			return db_cursor.fetchall()
		else:
			return []