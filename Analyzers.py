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
# Error messages
#
ERR_FAIL_DATA_RET		=	"Could not retrieve data for '{:s}': {:s}"
ERR_INVALID_DEST_DIR	=	"Invalid destination folder: '{:s}'."
ERR_NULL_DATA_SOURCE	=	"Malware data source cannot be null."
#
# Information/Debug messages
#
MSG_INFO_NEXT_RUN		=	"Next run: {:%H:%M:%S}"
MSG_INFO_ANALYZING		=	"Analyzing '{:s}' ..."
WARN_NODATA_FOUND		=	"No data retrieved for '{:s}'."
INFO_THREAD_SHUTDOWN	=	"Analysis completed. Thread '{:s}' terminated."
#
#//////////////////////////////////////////////////////////////////////////////
#
#//////////////////////////////////////////////////////////////////////////////
#
class Analyzer(threading.Thread):

	# Default name for thread.
	DefaultThreadName  = "vx_pit_analyzer"

	# Default sleep time for the thread in seconds.
	DefaultWaitDelay = 10
	
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
			raise Exception(ERR_INVALID_DEST_DIR.format(_dst))
		
		#**********************************************************************
		# Set data source, raise exception if none provided.
		#**********************************************************************
		if (_vxdata != None):
			self.datasource = _vxdata
		else:
			raise Exception(ERR_NULL_DATA_SOURCE)
		
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
			#******************************************************************
			# Get the files currently in the pit. 
			#******************************************************************
			vx_in_pit = []
			for f in os.listdir(vx_pit):
				vx_file = os.path.join(vx_pit, f)
				if os.path.isfile(vx_file):
					vx_in_pit.append(vx_file)
					
			#******************************************************************
			# Verifies if the pit contains any file.
			#******************************************************************
			if (len(vx_in_pit) > 0):
				#**************************************************************
				# Start analyzing files found in the pit.
				#**************************************************************
				for vx_file in vx_in_pit:
					self.logger.print_info(MSG_INFO_ANALYZING.format(vx_file))
					
					#**********************************************************
					# Create a Virus object to manipulate the malware.
					#**********************************************************
					vx = Virus()
					vx.add_file(vx_file)
					vx.add_size(os.path.getsize(vx_file))
					
					try:
						vx_dst_file = ""
						#******************************************************
						# Retrieve the information about the file from the
						# given data source.
						#******************************************************
						self.datasource.retrieve_metadata(vx)
						vxdata = vx.get_antiviral_results()
						
						#*******************************************************
						# Verifies if data was retrieved from the data source.
						#*******************************************************
						if (vxdata and len(vxdata) > 0):
							self.logger.print_debug("File:{:s}:".format(vx_file))
							
							#***************************************************
							# Only store identifications with useful information,
							# discard data without idents.
							#***************************************************
							for (av, detection) in vxdata.iteritems():
								if (detection.lower().strip() != Virus.NOT_DETECTED):
									self.logger.print_debug("\t{:s}:{:s}".format(av, detection))
									vx.add_ident(av, detection)
							
						else:
							self.logger.print_warning(WARN_NODATA_FOUND.format(vx_file))
							
						#******************************************************
						# Archive the malware into the vault.
						#******************************************************
						self.vault.archive_file(vx)
						
					except Exception as e:
						self.logger.print_error(ERR_FAIL_DATA_RET.format(vx_file, str(e.message)))
						
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