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
# <date>2015-03-26</date>
# <url>https://github.com/infectedpacket</url>

__version_info__ = ('0','1','0')
__version__ = '.'.join(__version_info__)

#//////////////////////////////////////////////////////////////////////////////
# Imports Statements
#
import os
import os.path
#
from Vault import Vault
from Virus import Virus
from Logger import Logger
from DataSources import *
from Analyzers import *
from Archivers import *
#
from VaultExceptions import *
from Hunters import *
#
#//////////////////////////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////////////////////////
# Constants
ERR_MAX_ANALYZER_THREADS	=	"Maximum number of concurrent Analyzer objects reached."
INFO_CONNECTED_INTERNET		=	"Successfully connected to the Internet."
INFO_HUNT_THREADS_START		=	"Starting the hunters..."
INFO_HUNT_MALCODE_STARTED	=	"Started Malc0de hunter."
INFO_HUNT_LOCAL_STARTED		=	"Started local url hunter. Watching for files in '{:s}'."
MSG_INFO_DOWNLOADING	=	u"Downloading {:s} from {:s}."
DS_VIRUS_TOTAL = "VirusTotal"
UNALLOWED_CHARS_FILES	=	"/?<>\:*|\"^"
DEFAULT_REPLACE_CHAR	=	"_"
#//////////////////////////////////////////////////////////////////////////////

class Engine(object):

#******************************************************************************
# Class Static Variables
#
	DefaultDataSource = DS_VIRUS_TOTAL
#
# URL to use for testing Interner connectivity.
	UrlTestInternet = "https://www.google.com/"
#
#******************************************************************************


	def __init__(self, _base, _vtapi, 
		_password=Vault.DefaultArchivePassword, 
		_saveFileNoDetection=False,
		_logger=None):
		"""Initializes the engine, including the logger, vault and
		other class variables.

		Creates a default logger if none provided. The constructor
		also creates the data sources required to identify malware. Finally
		it will create a Vault object with the given base parameter.

		Args:
			_base: 
				The directory in which the filesystem of the vault will
				be created.
			_vtapi: 
				The public API key used to make requests to VirusTotal.
			_password:
				Password to use on archive creation.
			_saveFileNoDetection:
				Specified whether analyzed files undetected by no AV
				software should be saved in the archive.
			_logger: 
				Logger object to output information about program 
				execution. If none provided, it will use sys.stdout
				by default.

		Returns:
			None.

		Raises:
			None.
		"""
		#**************************************************************************
		# Creates a new logger object.
		#**************************************************************************
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		#**************************************************************************
		# Initializes an empty dictionary of data sources,
		# adds the VirusTotal data source object to it.
		#**************************************************************************
		self.data_sources = {}
		self.data_sources[DS_VIRUS_TOTAL] = VirusTotalSource(
			_vtapi, _logger=self.logger)

		#**************************************************************************
		# Initializes a new vault object with the
		# given base directory.
		#**************************************************************************
		self.vxvault = Vault(_base, _logger=self.logger)
		
		self.saveUndetectedFiles = _saveFileNoDetection
		self.active_hunters = []
		
	def __str__(self):
		return "<Engine>"
		
	def __repr__(self):
		return "<VxVault Engine {:s}>".format(__version__)
		
	def is_windows(self):
		"""Verifies if the current underlying operating system
		is Windows-based.

		This function verifies if the current underlying operating system
		is Windows-based.

		Args:
			None.

		Returns:
			True if the program is running on a Windows platform, False
			otherwise.

		Raises:
			None.
		"""	
		return ("win" in platform.system().lower())

	def set_archiver(self, _archiver):
		"""Sets the Archiver object to be used by the vault.

		This function will sets the Archiver to be used
		by the Vault to archive and compress malware into the filesystem.

		Args:
			Archiver object.

		Returns:
			None.

		Raises:
			None.
		"""	
		if (_archiver):
			self.vxvault.set_archiver(_archiver)
		else:
			raise FileNotFoundException(_program)
		
	def get_archiver(self):
		"""Returns the Archiver object currently used by the vault.

		This function will return the Archiver object currently used
		by the Vault to archive and compress malware into the filesystem.

		Args:
			None.

		Returns:
			Archiver object.

		Raises:
			None.
		"""		
		return self.archiver		
		
	def create_vault(self):
		"""Creates a new file system.

		This function will create the file system at the
		base specified at the creation of the engine. it will
		also initialize the vault.

		Args:
			None.

		Returns:
			None

		Raises:
			Exception if there was an error while creating 
			the file system.
		"""	
		self.vxvault.create_vault()	
		
	def vault_is_created(self):
		"""Verifies if the vault has been created at the base
		directory.

		This function will confirm if the vault has been created
		on the file system.

		Args:
			None.

		Returns:
			True if the vault has been created in the configured base
			directory provided at the creation of the engine. Returns 
			False otherwise.

		Raises:
			None.
		"""		
		return self.vxvault.is_created()

	def get_vault(self):
		"""
		Returns the vault object used by the engine.
		
		Args:
			None.
		
		Returns:
			Vault object associated with the engine.
			
		Raises:
			None.
		"""
		return self.vxvault
		
	def can_connect_internet(self):
		"""Verifies if a connection to the Internet is available.

		this function verifies if a connection to the Internet is
		available by attempting to connect to the website specified
		in Engine.UrlTestInternet.

		Args:
			None.

		Returns:
			True if the function was able to successfully connect
			to the specified website.
		Raises:
			Exception if an error occured while connecting to the
			site.
		"""	
		self.logger.print_debug("Attempting to connect to '{:s}'.".format(self.UrlTestInternet))
		request = urllib2.Request(self.UrlTestInternet)
		try:
			response = urllib2.urlopen(request)
			html = response.read()
			self.logger.print_debug(INFO_CONNECTED_INTERNET)
			return True
		except Exception as e:
			self.logger.print_debug(ERR_FAILED_CONNECT_NET.format(e.message))
			return False;			

	def add_http_file_virus(self, _url):
		"""
			Downloads a file at the specified URL into the pit directory of the
			vault and analyzes it prior to storing it in the vault.
			
			This function will download a file specified by a HTTP/HTTPS URL and
			save it to the "pit" directory. It will then proceed into 
			retrieving scan information for the downloaded file and archive it
			into the vault.
			
			TODO:
			[ ] Test this function.
			
			Args:
				_url: The URL of the file to download. Must start with HTTP.
				
			Returns:
				None.
				
			Raises:
				InvalidUrlException: If the provided URL is invalid.
				NullOrEmptyArgumentException: if the URL or destination path is empty or null.
				FileDownloadException: If the function failed to create the local file.				
		"""
		url = _url.strip()
		if (url and len(url) > 0):
			#******************************************************************
			# Verifies if the URL provided is valid
			#******************************************************************
			if (url[0:4].lower() == "http"):
				#******************************************************************
				# Build the destination path of the file.
				#******************************************************************
				dst_path = self.vxvault.get_pit()
				dst_file = url.split("/")[-1].strip()
				dst_file = self.replace_chars_in_string(dst_file, 
					UNALLOWED_CHARS_FILES, DEFAULT_REPLACE_CHAR)
				dst = os.path.join(dst_path, dst_file)
				if (os.path.exists(dst)):
					raise FileExistsException(dst)
				self.download_file(url, dst)
				#******************************************************************
				# Analyze the file downloaded after making sure it exists.
				#******************************************************************
				if (os.path.exists(dst)):
					self.add_single_file_virus(dst)
				else:
					raise FileDownloadException()
			else:
				raise InvalidUrlException(url)
		else:
			raise NullOrEmptyArgumentException()
		
	def replace_chars_in_string(self, _string, _chars, _replace):
		"""
			Replaces characters in the given string by a user-defined
			string.
			
			This functions will replace each instance of the characters specified
			in the _chars string found inthe _string argument with the characters
			specified in the _replace argument.
			
			Args:
				_string: String containing chars to be replaced
				_chars: String or array of characters to replaced.
				_replace: String or character used as replacement.
				
			Returns:
				None.
			
			Raises:
				None.
		"""
		new_string = _string
		for char in _chars:
			if char in _string:	
				new_string = new_string.replace()
		return new_string
	
	def download_file(self, _url, _dst):
		""" 
			Downloads a file at the specified URL into the local filesystem.
			
			This function will download a file specified by a HTTP/HTTPS URL and
			save it to the specified destination.
			
			Args:
				_url: The URL of the file to download. Must start with HTTP.
				_dst: Absolute path of the destination on the local file system.
				
			Returns:
				None.
				
			Raises:
				InvalidUrlException: If the provided URL is invalid.
				NullOrEmptyArgumentException: if the URL or destination path is empty or null.
				FileDownloadException: If the function failed to create the local file.
		
		"""
		url = urllib.unquote(_url.strip())
		if (url and len(url) > 0):
			#******************************************************************
			# Verifies if the URL provided is HTTP
			# Todo:
			#  [ ] Better URL validation function.
			#******************************************************************
			if (url[0:4].lower() == "http"):
				self.logger.print_info(MSG_INFO_DOWNLOADING.format(_dst, url))
				try:
					urllib.urlretrieve (url, _dst)
				except Exception as e:
					raise FileDownloadException("{:s}: {:s}".format(_dst, e.message))
			else:
				raise InvalidUrlException(url)
		else:
			raise NullOrEmptyArgumentException()
	
	def add_single_file_virus(self, _file):
		""" Adds a single file from the local system to the
		vault.
		
		This function will add a single file to the vault. It will
		analyze the file and attempt to identify it as a malware. Once
		completed, it will archive the file in a 7zip archive and move
		it into the vault based on the class and target OS.  This function
		will remove the original file from the source.
		
		Args:
			_file: The file to archive into the vault.
			
		Returns:
			None.
			
		Raises:
			Exception if provided file argument is null or empty. Will
			raise exception if the file cannot be found, or cannot connect
			to the Internet. Will also raise an exception if Analysis fails
			or archiving fails.
		"""
		#**********************************************************************
		# Verifies if the provided argument is valid.
		#**********************************************************************
		if (_file and len(_file) > 0):
			#******************************************************************
			# Checks if the file exists.
			#******************************************************************
			if (os.path.exists(_file)):
				#**************************************************************
				# Confirm if the file is not already stored in the vault
				#**************************************************************
				is_stored = self.file_is_archived(_file)
				if (is_stored):
					raise ArchiveExistsException(_file)
				
				#**************************************************************
				# Attempts to extract malware identification of
				# the given file.
				#**************************************************************
				datasrc = self.data_sources[DS_VIRUS_TOTAL]
				analyzer = Analyzer(
					_vxdata = datasrc,
					_vault = self.vxvault,
					_logger = self.logger)
				vx = analyzer.analyze_file(_file)
				if (vx):
					if (vx.is_detected() or 
						(vx.is_undetected and self.saveUndetectedFiles)):
						#******************************************************
						# Archives the file into the fault.
						#******************************************************
						self.vxvault.archive_file(vx)
			else:
				raise FileNotFoundException(_file)
		else:
			raise NullOrEmptyArgumentException()

	def add_single_dir_virus(self, _dir):
		""" Add a malware containing multiple files contained in a single
		directory.
		
		This function accepts a directory containing files of the same
		malware, bundles it into an archive and move it to the vault.
		
		Args:
			_dir: The directory containing the files of the malware.
			
		Returns:
			None.
			
		Raises:
			Exception if provided argument is null. Other exceptions on
			error retrieving data from the internet, directory not found,
			moving file to the vault or creating a new entry in the database.
		
		"""
		#**********************************************************************
		# Verifies if the provided argument is valid.
		#**********************************************************************
		if (_dir and len(_dir) > 0):
			#******************************************************************
			# Checks if the file exists.
			#******************************************************************
			if (os.path.isdir(_dir)):
				#**************************************************************
				# Check if the directory contains files
				#**************************************************************
				nb_files = len(os.listdir(_dir))
				if (nb_files == 0):
					raise Exception("Directory '{:s}' contains no file.".format(_dir))
					
				#**************************************************************
				# Attempts to extract malware identification of
				# the given file.
				#**************************************************************
				datasrc = self.data_sources[DS_VIRUS_TOTAL]
				analyzer = Analyzer(
					_vxdata = datasrc,
					_vault = self.vxvault,
					_logger = self.logger)
				vx = analyzer.analyze_dir(_dir)
				if (vx):
					#**********************************************************
					# Archives the file into the fault.
					#**********************************************************
					self.vxvault.archive_file(vx)
			else:
				raise FileNotFoundException(_dir)
		else:
			raise NullOrEmptyArgumentException()
		
	def add_multiple_virii_from_dir(self, _dir):
		""" Adds all files in the specified directory and subdirectories
		as individual malware.
		
		This function lists all files and subdirectories in the user-provided
		directory and adds each individual file to the vault as a individual
		malware. Subdirectories are considered as a single malware. All files in
		the subdirectory are considered part of the same malware.
		
		Args:
			_dir: The directory containing the malware
			
		Returns:
			None
			
		Raises:
			Exception on failure to find the directory, or if directory is empty.
			Exception if fail to analyze, store file into the vault or record
			the file into the database.
		
		"""
		#**********************************************************************
		# Verifies if the provided argument is valid.
		#**********************************************************************
		if (_dir and len(_dir) > 0):	
			#******************************************************************
			# Checks if the file exists.
			#******************************************************************
			if (os.path.isdir(_dir)):
				#**************************************************************
				# Check if the directory contains files
				#**************************************************************
				nb_files = len(os.listdir(_dir))
				if (nb_files == 0):
					raise Exception("Directory '{:s}' contains no file.".format(_dir))
					
				datasrc = self.data_sources[DS_VIRUS_TOTAL]
				analyzer = Analyzer(
					_vxdata = datasrc,
					_vault = self.vxvault,
					_logger = self.logger)

				for root, dirs, files in os.walk(_dir):
					for name in files:
						vx_file = os.path.join(root, name)
						#******************************************************
						# Confirm if the file is not already stored in the 
						# vault
						#******************************************************
						is_stored = self.file_is_archived(vx_file)
						if (is_stored):
							raise Exception(ERR_FILE_ALREADY_EXISTS.format(_file))						
						self.logger.print_debug("Adding file '{:s}'...".format(vx_file))
						vx = analyzer.analyze_file(vx_file)
						if (vx):
						#******************************************************
						# Archives the file into the fault.
						#******************************************************
							self.vxvault.archive_file(vx)
						#**********************************************************
						# Verifies if we are allowed to make a new request to
						# the data source.
						#**********************************************************
						next_run = datasrc.get_next_allowed_request()
						self.logger.print_debug(MSG_INFO_NEXT_RUN.format(next_run))						
						while (datetime.now() < next_run):
							time.sleep(3)
				
					for dir in dirs:
						vx_dir = os.path.join(root, dir)
						#**************************************************************
						# Check if the directory contains files
						#**************************************************************
						nb_files = len(os.listdir(vx_dir))
						if (nb_files == 0):
							raise Exception("Directory '{:s}' contains no file.".format(vx_dir))

						vx = analyzer.analyze_dir(vx_dir)
						if (vx):
							#**********************************************************
							# Archives the file into the fault.
							#**********************************************************
							self.vxvault.archive_file(vx)
						#**********************************************************
						# Verifies if we are allowed to make a new request to
						# the data source.
						#**********************************************************
						next_run = datasrc.get_next_allowed_request()
						self.logger.print_debug(MSG_INFO_NEXT_RUN.format(next_run))						
						while (datetime.now() < next_run):
							time.sleep(3)
							
			else:
				raise FileNotFoundException(_dir)
		else:
			raise NullOrEmptyArgumentException()
			
	def start_malware_hunt(self):
		"""
		
		"""
		
		hunt_malcode = MalcodeHunter(
			_engine=self,
			_logger=self.logger)
		
		self.active_hunters.append(hunt_malcode)
		
		for hunter in self.active_hunters:
			hunter.start()
	
	def stop_malware_hunt(self):
		"""
		
		"""
		for hunter in self.active_hunters:
			hunter.stop_hunting()
			hunter.join()
			
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
		return self.vxvault.file_is_archived(_file)
			
	def shutdown(self):
		"""Clean up function for the engine.
		
		This function will manage program termination.
		
		Args:
			None
		Returns:
			None.
		Raises:
			None.
		"""
		pass
		
