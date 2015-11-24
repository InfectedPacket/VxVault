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
import os
import sys
import simplejson
import urllib
import urllib2
import os.path
import platform
import traceback

from Vault import Vault
from Virus import Virus
from Logger import Logger
from DataSources import *
from Hunters import *
from Analyzers import *
from Archivers import *
#//////////////////////////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////////////////////////
# Constants
ERR_FAILED_CONNECT_NET		=	"Failed to connect to the Internet: {:s}."
ERR_MAX_ANALYZER_THREADS	=	"Maximum number of concurrent Analyzer objects reached."
ENGINE_ERROR_INVALID_FILE	=	"Invalid file: {:s}."
ENGINE_ERROR_ARCHIVER_404	=	"Could not find archiving program: {:s}."
ENGINE_ERROR_UNKNOWN_TYPE	=	"Unknown file type: {:s}."
ENGINE_ERROR_NO_METADATA	=	"No metadata found for malware '{:s}'."

INFO_CONNECTED_INTERNET		=	"Successfully connected to the Internet."
INFO_HUNT_THREADS_START		=	"Starting the hunters..."
INFO_HUNT_MALCODE_STARTED	=	"Started Malc0de hunter."
INFO_HUNT_LOCAL_STARTED		=	"Started local url hunter. Watching for files in '{:s}'."
DS_VIRUS_TOTAL = "VirusTotal"

DEFAULT_DATA_SOURCE = DS_VIRUS_TOTAL

#//////////////////////////////////////////////////////////////////////////////

class Engine(object):

#******************************************************************************
# Class Variables
#
# Maximum number of Analyzer threads that can
# run concurrently.
	MaxActiveAnalyzers = 1
#
# URL to use for testing Interner connectivity.
	UrlTestInternet = "https://www.google.com/"
#
#******************************************************************************


	def __init__(self, _base, _vtapi, _logger=None):
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
		# Initializes an empty dictionary of data sources,
		# adds the VirusTotal data source object to it.
		self.data_sources = {}
		self.data_sources[DS_VIRUS_TOTAL] = VirusTotalSource(_vtapi)
		# Initializes the list of active hunters and 
		# analyzers threads.
		self.active_hunters = []
		self.active_analyzers = []
		# Initializes a new vault object with the
		# given base firectory.
		self.vxvault = Vault(_base, self.logger)
		
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
			raise Exception(ENGINE_ERROR_ARCHIVER_404.format(_program))
		
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
		self.vxvault.file_system.create_filesystem()	
		
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
			False otherwie.

		Raises:
			None.
		"""		
		return self.vxvault.is_created()
				
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

	def start_hunters(self):
		"""Initializes and start the hunting threads.

		This function creates the Hunter threads and 
		starts them. Each thread is kept in an array of
		active threads.

		Args:
			None.

		Returns:
			None.
		Raises:
			None.
		"""		
		self.logger.print_debug(INFO_HUNT_THREADS_START)
		#**********************************************************************
		# Retrieve the pit folder from the vault.
		#**********************************************************************
		vx_pit = self.vxvault.get_pit()
		
		#**********************************************************************
		# Create hunter objects
		#**********************************************************************
		hunter_malcode = MalcodeHunter(_pit=vx_pit, _logger=self.logger)
		self.logger.print_debug(INFO_HUNT_MALCODE_STARTED)
		hunter_local =  LocalHunter(
			_pit=vx_pit, 
			_dir=self.vxvault.file_system.get_urls_dump(),
			_logger=self.logger)
		self.logger.print_debug(INFO_HUNT_LOCAL_STARTED.format(
			self.vxvault.file_system.get_urls_dump()))
		#**********************************************************************
		# Add hunters to the list of active hunter
		# objects
		#**********************************************************************
		hunter_malcode.start()
		hunter_local.start()
		self.active_hunters.append(hunter_malcode)
		self.active_hunters.append(hunter_local)
		
	def start_analyzers(self):
		"""Initializes and start the analyzer threads.

		This function creates the Analyzer threads and 
		starts them. The Analyzer threads will look for new
		executable into the pit folder of the vault. For each
		executable found, the Analyzer will attempt to identify
		the malware and archive it at the proper location in the
		file system. Each Analyzer thread object is added to a 
		list of active threads.
		
		Args:
			None.

		Returns:
			None.
		Raises:
			None.
		"""
		#**********************************************************************
		# Virus Total source.
		#**********************************************************************
		vt_source = self.data_sources[DS_VIRUS_TOTAL]
		
		#**********************************************************************
		# Add each analyzer, which will be started once added.
		#**********************************************************************
		self._add_analyzer(vt_source)
		
	def _add_analyzer(self, _datasrc):
		"""Create and start a new analyzer thread.

		This function creates a new Analyzer thread with 
		the given data source. Once created, it is started
		and added to the list of active analyzer threads.
		
		Args:
			_datasrc A data source object use for identification
			of the malware found.

		Returns:
			None.
		Raises:
			Exception is the maximum number of analyzer threads reached.
		"""
		#**********************************************************************
		# Check if a valid data source has been provided.
		#**********************************************************************
		if (_datasrc):
			#******************************************************************
			# Check if we have reach the maximum number of active
			# threads has been reached.
			#******************************************************************
			if (len(self.active_analyzers) < Engine.MaxActiveAnalyzers):
				#**************************************************************
				# Create the Analyzer thread, add it to the list of active
				# analyzers and start the thread.
				#**************************************************************
				vx_vault = self.vxvault
				vx_analyzer = Analyzer(
					_vxdata	=	_datasrc, 
					_vault	=	vx_vault, 
					_logger	=	self.logger)
				self.active_analyzers.append(vx_analyzer)
				vx_analyzer.start()
			else:
				raise Exception(ERR_MAX_ANALYZER_THREADS)
		
	def shutdown(self):
		"""Stops all active threads and terminate any child process.

		This function will stops all hunters, analyzers and other
		threads stored in the threads list. If needed, it will also
		reset any required variables or objects.
		
		Args:
			None
		Returns:
			None.
		Raises:
			None.
		"""
		self.stop_analyzers()
		self.stop_hunters()
		
	def stop_hunters(self):
		"""Stops all active hunters threads.

		This function will stops all active hunters listed in the
		'active_hunters' list.
		
		Args:
			None
		Returns:
			None.
		Raises:
			None.
		"""
		for vx_hunter in self.active_hunters:
			vx_hunter.stop_hunting()
			if (vx_hunter.is_alive()):
				vx_hunter.join()
			
	def stop_analyzers(self):
		"""Stops all active analyzer threads.

		This function will stops all active analyzers listed in the
		'active_analyzers' list.
		
		Args:
			None
		Returns:
			None.
		Raises:
			None.
		"""
		for vx_analyzer in self.active_analyzers:
			vx_analyzer.stop_analysis()
			if (vx_analyzer.is_alive()):
				vx_analyzer.join()