#!/usr/bin/env python
# -*- coding: latin-1 -*-
#//////////////////////////////////////////////////////////////////////////////
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
# <date>2015-03-26</date>
# <url>https://github.com/infectedpacket</url>

#//////////////////////////////////////////////////////////////////////////////
# Imports Statements
#
import re
import shutil
import os.path
import threading
#
from datetime import datetime
from Virus import Virus
from DataSources import *
#
#//////////////////////////////////////////////////////////////////////////////
# Globals and Constants
#
# Information/Debug messages
#
MSG_INFO_NEXT_RUN		=	"Next run: {:%H:%M:%S}"
MSG_INFO_ANALYZING		=	"Analyzing '{:s}' ..."
WARN_NODATA_FOUND		=	"No data retrieved for '{:s}'."
INFO_THREAD_SHUTDOWN	=	"Analysis completed. Thread '{:s}' terminated."
#
DEFAULT_THREAD_NAME		=	"vx_pit_analyzer"
DEFAULT_WAIT_DELAY		=	10
#
#//////////////////////////////////////////////////////////////////////////////
#
#//////////////////////////////////////////////////////////////////////////////
#
class Analyzer(threading.Thread):

	# Default name for thread.
	DefaultThreadName  = DEFAULT_THREAD_NAME

	# Default sleep time for the thread in seconds.
	DefaultWaitDelay = DEFAULT_WAIT_DELAY
	
	def __init__(self, _vxdata, _vault, _logger=None):
		#**********************************************************************
		# Initialize the thread parent object
		#**********************************************************************
		threading.Thread.__init__(self)
		
		#**********************************************************************
		# Create Logger object.
		#**********************************************************************
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		
		#**********************************************************************
		# Set default name
		#**********************************************************************
		self.name = Analyzer.DefaultThreadName
		
		#**********************************************************************
		# Set stop flag.
		#**********************************************************************
		self.analyze = False
		
		#**********************************************************************
		# Set vault object, raise exception if invalid.
		#**********************************************************************
		if (_vault):
			self.vault = _vault
		else:
			raise NullOrEmptyArgumentException()
		
		#**********************************************************************
		# Set data source, raise exception if none provided.
		#**********************************************************************
		if (_vxdata != None):
			self.datasource = _vxdata
		else:
			raise NullOrEmptyArgumentException()
		
	def stop_analysis(self):
		"""Sets the stop flag to shutdown the thread.

		This function set the stop flag to indicate to the
		main loop of the thread to exit. When the thread
		wakes up, it checks if the flag has been set and if so,
		exits.
		
		Args:
			None.

		Returns:
			None.
		Raises:
			None.
		"""	
		self.analyze = False
		
	def run(self):
		"""Starts identifying files downloaded into the SUBFOLDER_PIT
		directory.

		This function is the core of the Analyzer threads. It will list
		files in the SUBFOLDER_PIT directory and start gathering information
		for each from the given data source. After each file, it will wait 
		until the timing provided by the 'get_next_allowed_request()' of the
		data source before starting the next file. For each file, it will
		then archive it by creating a Virus object and archving it
		into the Vault by calling the 'archive_file()' function.

		Args:
			None.

		Returns:
			None.

		Raises:
			None.
		"""
		self.analyze = True
		vx_pit = self.vault.get_pit()
		while (self.analyze):
			
			vx_objects = self.analyze_dir(vx_pit)
						
			#**********************************************************
			# The next_run variable holds the time of the next time the 
			# analyzer will move on to the other file.Some data sources 
			# allows only abs limited number of requests per 
			# minute/hour/etc...
			#**********************************************************
			self.next_run = self.datasource.get_next_allowed_request()
			self.logger.print_debug(MSG_INFO_NEXT_RUN.format(self.next_run))
			#**********************************************************
			# Verifies if the thread should resume with the analysis,
			# exit, or sleep some more.
			#**********************************************************
			while (datetime.now() < self.next_run and self.analyze):
				time.sleep(Analyzer.DefaultWaitDelay)

			if (not self.analyze):
				break
			else:
				self.logger.print_debug("No files found in pit.")
				time.sleep(Analyzer.DefaultWaitDelay)
				
		self.logger.print_warning(INFO_THREAD_SHUTDOWN.format(self.name))
		
	def analyze_dir(self, _dir):
		""" Creates a Virus object containng all files in the specifiled directory
		and retrieves metadata from each file found.
		
		Args:
			_dir: The directory containing files to analyze.
			
		Returns:
			Virus object containing information retrieved from the data
			source.
			
		Raises:
			Exception if the provided directory is null or empty.
		
		"""
		if (_dir and len(_dir) > 0):
			self.logger.print_info(MSG_INFO_ANALYZING.format(_dir))
			
			vx = Virus(_logger=self.logger)
			vx.add_dir(_dir)
			self.datasource.retrieve_metadata(vx)
			return vx
		else:
			raise NullOrEmptyArgumentException()
			
	def analyze_file(self, _file):
		""" Creates a Virus object with metadata retrieved from the given
		data source of the analyzer. 
		
		Args:
			_file: The file to analyze.
			
		Returns:
			Virus object containing information retrieved from the data
			source.
			
		Raises:
			Exception if the provided file is null or empty.
		
		"""
		if (_file and len(_file) > 0):
			self.logger.print_info(MSG_INFO_ANALYZING.format(_file))
			
			#**********************************************************
			# Create a Virus object to manipulate the malware.
			#**********************************************************
			vx = Virus(_logger=self.logger)
			vx.add_file(_file)

			vx_dst_file = ""
			#******************************************************
			# Retrieve the information about the file from the
			# given data source.
			#******************************************************
			try:
				self.datasource.retrieve_metadata(vx)
			except:
				pass
			return vx
		else:
			raise NullOrEmptyArgumentException()

