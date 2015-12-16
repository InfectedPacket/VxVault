#!/usr/bin/env python
# -*- coding: latin-1 -*-
#//////////////////////////////////////////////////////////////////////////////
#█▀▀▀▀█▀▀▀▀▀██▀▀▀▀██▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀▀▓▒▀▀▀▀▀▀▀▀▀▀█▓▀ ▀▀▀██▀▀▀▀▀▀▀▀▀▓▓▀▀▀▀▀▀▀▀▀
#▌▄██▌ ▄▓██▄ ▀▄█▓▄▐ ▄▓█▓▓▀█ ▄▓██▀▓██▓▄ ▌▄█▓█▀███▓▄ ▌▄█▓█ ▀ ▄▓██▀▓██▓▄ ▄█▓█▀███▄
#▌▀▓█▓▐▓██▓▓█ ▐▓█▓▌▐▓███▌■ ▒▓██▌ ▓██▓▌▐▓▒█▌▄ ▓██▓▌ ▐▓▒█▌▐ ▒▓██▌  ▓██▓▌▓▒█▌ ▓█▓▌
#▐▓▄▄▌░▓▓█▓▐▓▌ █▓▓▌░▓▓█▓▄▄ ▓▓██▓▄▄▓█▓▓▌░▓█▓ █ ▓█▓▓▌░▓█▓ ▒ ▓▓██▓▄▄▓█▓▓▌▓█▓ ░ ▓█▓
#▐▓▓█▌▓▓▓█▌ █▓▐██▓▌▐▓▒▓▌ ▄ ▐░▓█▌▄ ▀▀▀ ▐▓▓▓ ▐▌ ▀▀▀  ▐▓▓▓▄▄ ▐░▓█▌ ▄ ▀▀▀ ▓▓▓ ░ ██▓
#▐▓▓▓█▐▓▒██ ██▓▓▓▌▐▓▓██  █▌▐▓▓▒▌▐ ███░▌▐▓▓▒▌▐ ███░▌ ▐▓▓▒▌ ▐▓▓▒▌▀ ███░▌▓▓▒▌ ███░
# ▒▓▓█▌▒▓▓█▌ ▐▓█▒▒  ▒▓██▌▐█ ▒▓▓█ ▐█▓▒▒ ▒▒▓█  ▐█▓▒▒  ▒▒▓█ ▓▌▒▓▓█ ▐█▓▒▒ ▒▒▓█ ▐█▓▒
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
#//////////////////////////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////////////////////////
# Imports Statements
import os
import sys
import shutil
import os.path
import platform

from Virus import Virus
from Logger import Logger
from Archivers import SevenZipArchiver
from VaultDatabase import VaultDatabase
from VaultExceptions import *
#//////////////////////////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////////////////////////
# Constants
ERR_INVALID_OS_CLASS = "Invalid or empty operating system/malware class provided."

INFO_NEW_BASE	=	"Relocated file system to '{:s}'."
DEFAULT_ARCHIVE_PASSWORD = "infected"
INFO_MOVING_FILE = "Moving file '{:s}' to '{:s}'."
#//////////////////////////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////////////////////////
# Classes
class Vault(object):

	# Password used to archive malware.
	# TODO: 
	#	[X] User-provided from command line.
	DefaultArchivePassword = DEFAULT_ARCHIVE_PASSWORD

	def __init__(self, _base, _password="", _multipleSamplesAllowed = False, _logger=None):
		"""Initializes the Vault and the FileSystem objects.

		Creates a new Vault object which is used to interface
		with the file system of the operating system. 

		Args:
			_base: 
				The directory in which the filesystem of the vault will
				be created.
			_name:
				Optional name to identify the vault object.
			_logger: 
				Logger object to output information about program 
				execution. If none provided, it will use sys.stdout
				by default.

		Returns:
			None.

		Raises:
			None.
		"""	
		# Creates a new logger object.
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		# Initialize the FileSystem object with the given
		# base.
		self.file_system = FileSystem(_base, _logger=_logger)
		#
		# Initializes the database.
		#
		self.database = VaultDatabase(
			_file=self.file_system.get_db_file(),
			_logger=self.logger)
		#
		# Sets the archiver object for storing files in
		# the vault.
		#
		archive_program = SevenZipArchiver(
			_password = Vault.DefaultArchivePassword,
			_logger = self.logger
		)
		self.set_archiver(archive_program)
		self.multipleSamplesAllowed = _multipleSamplesAllowed
		
	def __repr__(self):
		return "<Vault '{:s}' @{:s}>".format(
			self.get_name(), self.file_system.get_base())
		
	def create_vault(self, _overwrite=False):
		""" Creates the database and filesystem of the vault.
		
		This function will first create the database file and schema. It
		will then create the filesystem to store the files. 
		
		Args:
			_overwrite: Optional. If set to true, will create the
			database and filesystem even if it already exists.
		Returns:
			None.
		Raises:
			None.
		"""
		self.database.create_database(_overwrite)
		self.file_system.create_filesystem(_overwrite)
		
	def is_created(self):
		"""Verifies if this vault has already been created
		in the filesystem.

		This function will confirm if the vault has been created
		on the file system.

		Args:
			None.

		Returns:
			True if the vault has been created in the configured base
			directory provided at the creation of the engine. Returns 
			False otherwie.

		Raises:
			None.
		"""	
		fs_is_created = self.file_system.filesystem_exists()
		db_is_created = self.file_system.database_file_exists()
		return fs_is_created and db_is_created
		
	def get_pit(self):
		"""Retrieves the absolute path of the SUBFOLDER_PIT
		directory.

		This function will retrieves the absolute path of the SUBFOLDER_PIT
		directory.

		Args:
			None.

		Returns:
			Absolute path of the SUBFOLDER_PIT directory.

		Raises:
			None.
		"""	
		return self.file_system.get_pit()
		
	def archive_file(self, _vx):
		""" Archives the files held in the given Virus object into
		an archive in the Vault.

		This function is a shortcut function to FileSystem.archive_file.

		Args:
			_vx: Virus object containing metadata about the malware.

		Returns:
			None.

		Raises:
			Exception if the provided Virus object is null.
		"""	
		self.file_system.archive_file(_vx)
		self.database.add_malware(_vx)

	def file_is_archived(self, _file):
		""" Verifies if the given file is already stored in one of the
		archive in the vault.
		
		This function is a shortcut to VaultDatabase.file_exists.
		
		Args:
			_file: Absolute path of the file to verify.
			
		Returns:
			True if the SHA1 hash of the given file is found in the Files table
			of the database. False otherwise.
			
		Raises:
			Exception if null or empty arguments. Raise exception if given
			file is not found.
			
		"""
		self.logger.print_info("Verifying if file '{:s}' is already archived.".format(_file))
		if (_file and len(_file) > 0):
			return self.database.file_exists(_file)
		else:
			raise NullOrEmptyArgumentException()
		
	def set_archiver(self, _archiver):
		""" Sets the Archiver to be used by the Vault to archive and 
		compress malware into the filesystem.

		This function sets the Archiver to be used by the Vault to archive and 
		compress malware into the filesystem.

		Args:
			_archiver: An Archiver object.

		Returns:
			None.

		Raises:
			Exception if the provided Virus object is null.
		"""	
		self.file_system.set_archiver(_archiver)
		
class FileSystem(object):

	#**************************************************************************
	# Name of the vault database file.
	#**************************************************************************
	VAULT_DB 			= ".vault.db"

	#**************************************************************************
	# Constants of operating systems used to create the
	# file system.
	#**************************************************************************
	SUBFOLDER_WINDOWS 	= "win"
	SUBFOLDER_MSDOS 	= "msdos"
	SUBFOLDER_LINUX 	= "linux"
	SUBFOLDER_UNIX 		= "unix"
	SUBFOLDER_OSX 		= "osx"
	SUBFOLDER_ANDROID	= "android"
	SUBFOLDER_WEB		= "web"
	SUBFOLDER_ANY		= "any"
	SUBFOLDER_OTHERS	= "misc"
	SUBFOLDER_PIT		= "pit"
	
	#**************************************************************************
	# Constants of malware classes used to create the
	# file system.
	#**************************************************************************	
	SUBFOLDER_VIRUS		= "virus"
	SUBFOLDER_WORM		= "worm"
	SUBFOLDER_ADWARE	= "adware"
	SUBFOLDER_TROJAN	= "trojan"
	SUBFOLDER_ROOTKIT	= "rootkit"
	SUBFOLDER_EXPLOITKIT= "exploitkit"
	SUBFOLDER_RAT		= "rat"
	SUBFOLDER_WEBSHELL	= "web"
	SUBFOLDER_CRYPTER	= "crypter"
	SUBFOLDER_SPYWARE	= "spyware"
	SUBFOLDER_MISC		= "others"
	SUBFOLDER_URLS		= "urls"
	
	#**************************************************************************
	# List of operating systems used to create the
	# file system.
	#**************************************************************************	
	OperatingSystems = [SUBFOLDER_WINDOWS,
						SUBFOLDER_MSDOS,
						SUBFOLDER_LINUX,
						SUBFOLDER_UNIX,
						SUBFOLDER_OSX,
						SUBFOLDER_ANDROID,
						SUBFOLDER_WEB,
						SUBFOLDER_ANY,
						SUBFOLDER_OTHERS]
				
	#**************************************************************************
	# List of malware classes used to create the
	# file system.
	#**************************************************************************	
	MalwareClasses = [SUBFOLDER_VIRUS,
						SUBFOLDER_WORM,
						SUBFOLDER_ADWARE,
						SUBFOLDER_TROJAN,
						SUBFOLDER_ROOTKIT,
						SUBFOLDER_EXPLOITKIT,
						SUBFOLDER_RAT,
						SUBFOLDER_WEBSHELL,
						SUBFOLDER_CRYPTER,
						SUBFOLDER_SPYWARE,
						SUBFOLDER_MISC]
					
	#**************************************************************************
	# Defines the subdirectories for each operating system
	# directory.
	#**************************************************************************	
	MsDosSubFolders = [SUBFOLDER_VIRUS, SUBFOLDER_WORM, SUBFOLDER_TROJAN, SUBFOLDER_ROOTKIT]
	LinuxSubFolders = MsDosSubFolders + [SUBFOLDER_RAT,SUBFOLDER_SPYWARE]		
	WindowsSubFolders = LinuxSubFolders +[SUBFOLDER_CRYPTER,SUBFOLDER_EXPLOITKIT]
	AndroidSubFolders = LinuxSubFolders +[SUBFOLDER_EXPLOITKIT]	
	WebSubFolders = [SUBFOLDER_WEBSHELL, SUBFOLDER_EXPLOITKIT]
	PitSubFolders = [SUBFOLDER_URLS]

	#**************************************************************************
	# Defines the structure of the  file system.
	#**************************************************************************
	FileStructure = {
		SUBFOLDER_WINDOWS 	:	WindowsSubFolders,
		SUBFOLDER_MSDOS 	:	MsDosSubFolders,
		SUBFOLDER_LINUX 	:	LinuxSubFolders,
		SUBFOLDER_UNIX 		:	LinuxSubFolders,
		SUBFOLDER_OSX 		:	LinuxSubFolders,
		SUBFOLDER_ANDROID 	:	AndroidSubFolders,
		SUBFOLDER_WEB		: 	WebSubFolders,
		SUBFOLDER_ANY		: 	WindowsSubFolders,		
		SUBFOLDER_OTHERS 	:	[],
		SUBFOLDER_PIT 		:	PitSubFolders
	}

	#**************************************************************************
	# Dictionary to translate targeted operating system of
	# malware to the corresponding directory in the file system.
	#**************************************************************************
	OsToFolder = {
		Virus.VX_OS_DOS				: SUBFOLDER_MSDOS,
		Virus.VX_OS_WIN16			: SUBFOLDER_WINDOWS,
		Virus.VX_OS_WIN32			: SUBFOLDER_WINDOWS,
		Virus.VX_OS_WIN64			: SUBFOLDER_WINDOWS,
		Virus.VX_OS_LINUX_32		: SUBFOLDER_LINUX,
		Virus.VX_OS_LINUX_64		: SUBFOLDER_LINUX,
		Virus.VX_OS_ANDROID			: SUBFOLDER_ANDROID,
		Virus.VX_OS_MACOS			: SUBFOLDER_OSX,
		Virus.VX_OS_WEB				: SUBFOLDER_WEB,
		Virus.VX_OS_ANY				: SUBFOLDER_ANY,
	}
	
	#**************************************************************************
	# Dictionary to translate class of
	# malware to the corresponding directory in the file system.
	#**************************************************************************
	ClassToFolder = {
		Virus.VX_CLASS_VIRUS 		: SUBFOLDER_VIRUS,
		Virus.VX_CLASS_ADWARE		: SUBFOLDER_ADWARE,
		Virus.VX_CLASS_WORM			: SUBFOLDER_WORM,
		Virus.VX_CLASS_TROJAN 		: SUBFOLDER_TROJAN,
		Virus.VX_CLASS_ROOTKIT		: SUBFOLDER_ROOTKIT,
		Virus.VX_CLASS_EXPLOIT		: SUBFOLDER_EXPLOITKIT,
		Virus.VX_CLASS_SPYWARE		: SUBFOLDER_SPYWARE,
		Virus.VX_CLASS_WEBSHELL		: SUBFOLDER_WEBSHELL,
		Virus.VX_CLASS_CRYPTER		: SUBFOLDER_CRYPTER,
		Virus.VX_CLASS_BACKDOOR		: SUBFOLDER_ROOTKIT,
		Virus.VX_CLASS_KEYLOGGER	: SUBFOLDER_SPYWARE,
		Virus.VX_CLASS_OTHER		: SUBFOLDER_MISC
	}
	
	def __init__(self, _base, _logger=None):
		#**********************************************************************
		# Creates a new logger object.
		#**********************************************************************
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		
		#**********************************************************************
		# Sets the base directory of the vault.
		#**********************************************************************
		self.set_base(_base)
		
		#**********************************************************************
		# Create the database of the vault.
		#**********************************************************************
		self.database = VaultDatabase(self.get_db_file)
		
		#**********************************************************************
		# Specify the first level of directories to create in the base
		# directory, i.e. list of operating systems.
		#**********************************************************************
		self.FileStructure[self.get_base()] = FileSystem.OperatingSystems
		
	def __repr__(self):
		return "<Filesystem @{:s}>".format(self.get_base())
		
	def set_base(self, _base):
		"""Sets the base directory of the vault on the underlying
		file system.

		This function sets the base directory of the vault on the underlying
		file system. The first level of directories, i.e. directories
		for operating systems, will be created in the folder provided 
		in this function.

		Args:
			_base : a path indicating the location of the vault
			and the vault database.

		Returns:
			None.

		Raises:
			Exception if the given base is invalid, i.e. not found or
			is not a directory.
		"""			
		if not os.path.isdir(_base):
			raise FileNotFoundException(_base)
		self.logger.print_debug(INFO_NEW_BASE.format(_base))
		self.base = _base
		
	def get_base(self):
		"""Returns the base directory of the vault on the underlying
		file system.

		This function returns the base directory of the vault on the underlying
		file system. The first level of directories, i.e. directories
		for operating systems, will be created in the folder provided 
		in this function.

		Args:
			None.

		Returns:
			A path indicating the location of the vault
			and the vault database.

		Raises:
			None.
		"""			
		return self.base
	

	def set_archiver(self, _archiver):
		""" Sets the Archiver to be used by the Vault to archive and 
		compress malware into the filesystem.

		This function sets the Archiver to be used by the File system to 
		archive and compress malware into the filesystem.

		Args:
			_archiver: An Archiver object.

		Returns:
			None.

		Raises:
			Exception if the provided Archiver object is null.
		"""	
		if (_archiver):
			self.archiver = _archiver
		else:
			raise NullOrEmptyArgumentException()
	
	def get_db_file(self):
		"""Returns the absolute path of the database file.

		Returns the absolute path of the database file linked
		to this vault object. 

		Args:
			None.

		Returns:
			The absolute path of the database file.

		Raises:
			None.
		"""		
		return os.path.join(self.get_base(), FileSystem.VAULT_DB)
	
	def get_pit(self):
		"""Retrieves the absolute path of the SUBFOLDER_PIT
		directory.

		This function will retrieves the absolute path of the SUBFOLDER_PIT
		directory.

		Args:
			None.

		Returns:
			Absolute path of the SUBFOLDER_PIT directory.

		Raises:
			None.
		"""	
		return os.path.join(self.get_base(), FileSystem.SUBFOLDER_PIT)
	
	def database_file_exists(self):
		""" Verifies that the database file exists on the filesystem.
		
		This functions verifies if the database file exists on the
		file systems. It does not verify that the actual database
		schema is created.
		
		Args:
			None.
			
		Returns:
			True, if the database file exists, false otherwise.
			
		Raises:
			None.
		"""
		return os.path.exists(self.get_db_file())
	
	def get_urls_dump(self):
		return os.path.join(self.get_pit(), FileSystem.SUBFOLDER_URLS)
	
	def get_directory(self, _os, _class):
		"""Finds the corresponding directory of the Vault based on the
		provided operating system and malware class.

		This function will leverage the FileSystem.OsToFolder and
		FileSystem.ClassToFolder to find the folder corresponding
		to the given properties. 

		Args:
			_os : Operating system.
			_class: Malware class, i.e. Trojan, Rootkit, Worm etc...

		Returns:
			The absolute path corresponding to the given OS and class properties.

		Raises:
			Exception if provided arguments are null/empty.
		"""	
		if (len(_os) > 0 and len(_class) > 0):
			abs_path = self.get_base()
			#******************************************************************
			# Find the directory corresponding to the OS of the
			# malware. If none found, used the OTHERS folder.
			#******************************************************************
			if (_os in FileSystem.OsToFolder):
				abs_path = os.path.join(abs_path, FileSystem.OsToFolder[_os])
			else:
				abs_path = os.path.join(abs_path, FileSystem.SUBFOLDER_OTHERS)
	
			#******************************************************************
			# Find the directory corresponding to the class of the
			# malware. If none found, used the OTHERS folder.
			#******************************************************************
			if (_class in FileSystem.ClassToFolder):
				abs_path = os.path.join(abs_path, FileSystem.ClassToFolder[_class])
			else:
				abs_path = os.path.join(abs_path, FileSystem.SUBFOLDER_MISC)
			
			return abs_path
		else:
			raise Exception(ERR_INVALID_OS_CLASS)
	
	def create_filesystem(self,_overwrite=False):
		"""Creates the file system on the disk.

		This function will create the file system on the disk
		to be used by the fault to archive malware.

		Args:
			None.

		Returns:
			None

		Raises:
			Exception if the base is invalid or an error occured
			while creating the directories.
		"""	
		if (self.get_base() and os.path.isdir(self.get_base())):
			# The first level of directories are operating
			# systems.
			for (os_dir, class_dirs) in FileSystem.FileStructure.iteritems():
				# Create the directory of the operating system
				# if it is not already existing.
				directory = os.path.join(self.get_base(), os_dir)
				if not os.path.exists(directory) or _overwrite:
					os.makedirs(directory)
					self.logger.print_debug("Created '{:s}'".format(directory))
				#
				# Get the subdirectories for this operating system.
				#
				for s in class_dirs:
					# Create each subdirectory if it is not already
					# existing.
					subdir = os.path.join(directory, s)
					if not os.path.exists(subdir) or _overwrite:
						os.makedirs(subdir)
						self.logger.print_debug("Created '{:s}'".format(subdir))
		else:
			raise FileNotFoundException(self.base)
	
	def filesystem_exists(self):
		"""Verifies if this vault has already been created
		in the filesystem.

		This function will confirm if the vault has been created
		on the file system. It checks if a database file exists
		in the base folder. This function then checks if all
		directories and sub-directories defined in the FileSystem.FileStructure
		dictionary object exists within the base folder. If one is missing,
		the function will return false.

		Args:
			None.

		Returns:
			True if the vault database file has been created in the 
			base folder and each directory defined in FileSystem.FileStructure
			exists. Returns False otherwise.

		Raises:
			Exception if the configured base directory is empty or invalid.
		"""	
		if (self.get_base() and os.path.isdir(self.get_base())):
			# Verifies if the file exists.
			if (self.database_file_exists()):
				# Start checking if every directory exists.
				for (os_dir, class_dirs) in FileSystem.FileStructure.iteritems():
					os_dir = os.path.join(self.get_base(), os_dir)
					if (not os.path.isdir(os_dir)):
						# Current directory not found. Return false.
						self.logger.print_debug(ERR_DIR_NOT_FOUND.format(os_dir))
						return False
					else:
						for class_dir in class_dirs:
							class_dir = os.path.join(os_dir, class_dir)
							if (not os.path.isdir(class_dir)):
								# Current sub-directory not found. Return false.
								self.logger.print_debug(ERR_DIR_NOT_FOUND.format(class_dir))
								return False
			else:
				self.logger.print_debug(ERR_DB_NO_DB_FILE.format(self.get_db_file()))
				return False
			
			return True
		else:
			raise FileNotFoundException(self.base)
			
	def archive_file(self, _vx, _password=Vault.DefaultArchivePassword, _multipleSamplesAllowed=False):
		"""Archives the malware into the file system.

		This function will archive the file(s) contained in the Virus
		object into an archive file format. The archive will be created
		to the vault with the password specified. The archive will be place
		in the directory corresponding to its class and targeted operating
		system.

		Args:
			_vx : The virus object containing malware information.
			_password: Password to use for the archive. If none specified,
			the value in Vault.DefaultArchivePassword will be used.

		Returns:
			None

		Raises:
			Exception if the received Virus object is null.
		"""	
		#
		# Verifies a valid Virus object was received (not null)
		#
		if (_vx):
			#
			# Ensure the properties of the malware have 
			# been captured.
			#
			_vx.generate_properties()
			#
			# Gets the os and class of the malware
			#
			vx_os = _vx.get_os()
			vx_class = _vx.get_class()
			#
			# Gets the path corresponding to the os and class
			# of the malware.
			#
			dst_path = self.get_directory(vx_os, vx_class)
			
			#
			# Move the file from its current location to the
			# vault.
			#
			_vx.set_password(_password)
			archive_name = self.archiver.archive(_vx, dst_path, 
				_multipleSamplesAllowed = _multipleSamplesAllowed)

			#
			# Delete the original files from the pit. Prevents
			# from re-analyzing them and saves space.
			#
			files_to_del = [f.get_absolute() for f in _vx.get_files()]
			for file_to_del in files_to_del:
				self.logger.print_warning("Deleting '{:s}'...".format(file_to_del))
				os.remove(file_to_del)

		else:
			raise NullOrEmptyArgumentException()

	def archive_exists(self, _archive):
		""" Verifies if the given archive already exists on the file system.
		
		This function will verify if the specified file is already created on 
		the file system solely based on the absolute path and filename.
		
		Args:
			_archive: Absolute path of the archive.
			
		Returns:
			True if a file with a similar name and path was found in the vault,
			False otherwise.
			
		Raises:
			None.
		"""
		return os.path.exists(_archive)