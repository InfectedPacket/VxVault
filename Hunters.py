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
# <date>2015-03-26</date>
# <url>https://github.com/infectedpacket</url>

#//////////////////////////////////////////////////////////
# Imports Statements
import os
import re
import abc
import sys
import time
import urllib
import urllib2
import threading
import feedparser
from Logger import Logger
from datetime import datetime, timedelta
from BeautifulSoup import BeautifulSoup
from VaultExceptions import *
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Globals and Constants

FILE_EXE	=	"exe"
FILE_DLL	=	"dll"
FILE_SCR 	=	"scr"
FILE_DOC	=	"doc"
FILE_PDF	=	"pdf"
FILE_APK	=	"apk"
FILE_JAR	=	"jar"
FILE_DOCX	=	"docx"
FILE_ZIP	=	"zip"

HTTP_URL_FORMAT = u"http://{:s}"	

ERR_INVALID_DEST_DIR	=	"Invalid directory: '{:s}'."
ERR_FAILED_PARSE_MALCODE=	"Failed to parse MalC0de feed : '{:s}'."
ERR_FAILED_DOWNLOAD		=	u"Failed to download file '{:s}': {:s}."
ERR_FILE_NO_CONTENTS	=	"No contents found in '{:s}'."

MSG_INFO_CONNECTING 	=	"Connecting to '{:s}'..."
MSG_INFO_DOWNLOADING	=	u"Downloading {:s} from {:s}."
MSG_INFO_NB_ENTRIES		=	"{:d} new entries found."
MSG_INFO_NEXT_RUN		=	"Next run: {:%H:%M:%S}"

MSG_WARN_NB_ENTRIES		=	"Considering only {:d} entries."
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Classes
#
class Hunter(threading.Thread):
	__metaclass__ = abc.ABCMeta

	DefaultThreadName = "vx-hunter"
	DefaultHuntWait = 10
	DefaultHuntInterval = 3600
	HuntedExtensions = [
		FILE_EXE, 
		FILE_DLL, 
		FILE_SCR, 
		FILE_DOC, 
		FILE_PDF, 
		FILE_APK, 
		FILE_JAR, 
		FILE_DOCX, 
		FILE_ZIP
	]

	def __init__(self, _engine, _extensions = HuntedExtensions, _logger=None):
		#**********************************************************************
		# Initializes the thread object.
		#**********************************************************************
		threading.Thread.__init__(self)
		#**********************************************************************
		# Creates a new logger object.
		#**********************************************************************
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger	
		
		#**********************************************************************
		# Sets properties of the hunter.
		#**********************************************************************
		self.name=Hunter.DefaultThreadName
		self.is_hunting = True
		
		self.extensions = _extensions
		
		if (_engine):
			self.engine = _engine
			#******************************************************************
			# Sets download location.
			#******************************************************************
			self.pit = _engine.get_vault().get_pit()
		else:
			raise NullOrEmptyArgumentException()

	def stop_hunting(self):
		"""
			Flags the thread to stop scanning/hunting.
			
			This functions sets the hunting flag to False, which will
			cause the main loop of the thread to exit.
			
			Args:
				None.
				
			Returns:
				None.
				
			Raises:
				None.
		"""
		self.is_hunting = False;
	
	@abc.abstractmethod
	def get_new_urls_since(self, _date, _max=150):
		return
	
	def run(self):
	
		while (self.is_hunting):
			#******************************************************************
			# Retrieves the new urls to download from the
			# child class.
			#******************************************************************
			new_targets = self.get_new_urls_since(datetime.now())
			
			#******************************************************************
			# Processes all new urls retrieved, if any.
			#******************************************************************
			for vx_url in new_targets:
				try:
					#**********************************************************
					# Use the engine to add the newly found URL to the
					# vault.
					#**********************************************************
					self.engine.add_http_file_virus(vx_url)
				except Exception as e:
					self.logger.print_error(e.message)
			
				#**************************************************************
				# To prevent flooding the data source with requests,
				# we wait for a few seconds.
				#**************************************************************
				self.next_hunt = datetime.now() + timedelta(seconds=Hunter.DefaultHuntInterval)
				self.logger.print_info(MSG_INFO_NEXT_RUN.format(self.next_hunt))
			
			while (datetime.now() < self.next_hunt and self.is_hunting):
				if self.is_hunting == True:
					time.sleep(Hunter.DefaultHuntWait)
			
		self.logger.print_warning(INFO_HUNT_COMPLETE.format(self.name))
		
class MalcodeHunter(Hunter):

	DefaultThreadName = u"vx-hunter-malcode"
	MalcodeRssSummarySeparator = u":"
	MalcodeRssContentsSeparator = u","	
	
	URL = 'http://malc0de.com/rss/'
	URL_MARKER = "URL:"
	
	def __init__(self, _engine, _extensions = Hunter.HuntedExtensions, _logger=None):
		super(MalcodeHunter, self).__init__(_engine, _extensions, _logger)	
		self.name=MalcodeHunter.DefaultThreadName
		self.last_entry = u""
	
	def get_new_urls_since(self, _date, _max=150):
		"""
		
		Note: Malc0de does not include dates within their posts on their RSS feed,
		so this method returns the maximum number of entries when used for the first
		time, or all entries between the current run and the last one.
		
		Args:
			_date: Last time the source was checked for new malware.
			_max: Maximum number of entries to consider.
			
		Returns:
			Array of strings representing URLs to malware files.
			
		Raises:
			None.
		"""
		urls = []
		
		#**********************************************************************
		# Retrieve the RSS feed from Malcode:
		#**********************************************************************
		self.logger.print_debug(MSG_INFO_CONNECTING.format(MalcodeHunter.URL))
		malcode_rss = feedparser.parse(MalcodeHunter.URL)

		#**********************************************************************
		# Start processing entries if any where found.
		#**********************************************************************
		if (len(malcode_rss.entries) > 0):
			#
			# Verifies if some of the entries are new. I.e. check all the 
			# entries between the first one retrieve and the last entry processed
			# and stored in self.last_entry
			# TODO:
			#	[ ] Value of self.last_entry should be retrieved from the database.
			nb_entries = 0
			while (self.last_entry != malcode_rss.entries[nb_entries] and nb_entries < _max):
				nb_entries += 1
					
			#
			# If new entries are found, start recoding them
			# if there's not already a sample in the vault (based on a hash)
			#
			if (nb_entries > 0):
				self.logger.print_info(INFO_NBENTRIES_FOUND.format(nb_entries))
				self.last_entry = malcode_rss.entries[0]
				
				for i in range(0, nb_entries):
					#
					# Information about the malware is stored in the summary
					# of the RSS post.
					#
					desc = malcode_rss.entries[i].summary.strip()
					
					desc_items = desc.split(MalcodeHunter.MalcodeRssContentsSeparator)
					url_data = desc_items[0]

					#**********************************************************
					# There should be 5 items in the summary of the post, if
					# not, then something is wrong, ignore it.
					#**********************************************************
					if (len(desc_items) == 5):
						if (MalcodeHunter.URL_MARKER in url_data):
							if (MalcodeHunter.MalcodeRssSummarySeparator in url_data):
								url_data = url_data.split(MalcodeHunter.MalcodeRssSummarySeparator)[1]
							url_data = url_data.strip()
							
							if (len(url_data) > 0):
								#**********************************************
								# Prepends "HTTP" at the beginning of the found 
								# URL, as it is usually not included.
								#**********************************************
								vx_url = url_data
								if (url_data[0:4].lower() != "http"):
									vx_url = HTTP_URL_FORMAT.format(url_data)
											
								#**********************************************
								# Retrieve the filename within the URL, so 
								# we can check if it's a file with an interesting
								# extension.
								#**********************************************
								vx_file = vx_url.split("/")[-1]	
								#**********************************************
								# If the file contains "?", we likely have a query
								# within the name, we need to weed it out.
								#**********************************************
								if (u"?" in vx_file):
									tmp_file = vx_file.split(u"?")
									#
									# TODO:
									# [ ] Check if the file is in the first
									# or second item of the split, ie.
									# file.exe?dl=1 or
									# download.php?file=bad.exe
									# Use a RE for this.
									vx_file = tmp_file[0]
							
								#**********************************************
								# Finally, get the extension and confirm we will
								# keep the URL.
								#**********************************************
								vx_ext = vx_file.split('.')[-1]
								#**********************************************
								# If the extension is greater than 5 chars, it's
								# probably a bad URL.
								#**********************************************
								if (len(vx_ext) > 5):
									vx_ext = ""

								if (vx_ext in self.extensions):
									urls.append(vx_url)
						else:
							self.logger.print_warning(ERR_NO_URL_POST.format(desc))
					else:
						self.logger.print_warning(ERR_FAILED_PARSE_MALCODE.format(desc))
			else:
				self.logger.print_warning(WARN_NO_NEW_ENTRIES)
		return urls	
		
class LocalHunter(Hunter):

	DefaultUrlRE = r'(h(tt|xx)ps?://[^\s]+)'

	def __init__(self, _engine, _files=[], _extensions = [], _logger=None):
		super(LocalHunter, self).__init__(_engine, _extensions, _logger)
		self.files = _files
		if (len(_extensions) > 0):
			ext_re = "|".join(_extensions)
			LocalHunter.DefaultUrlRE = r'(h(tt|xx)ps?://[^\s]+\.(' + ext_re + '))'
		
	def _get_urls_from_dir(self, _dir):
		if (_dir and len(_dir) > 0):
			if (os.path.exists(_dir)):
				urls = []
				
				for root, dirs, files in os.walk(_dir):
					for name in files:
						source_file = os.path.join(root, name)
						file_urls = self._get_urls_from_file(source_file)
						urls.append(file_urls)
				
				return urls
			else:
				raise FileNotFoundException(_dir)
		else:
			raise NullOrEmptyArgumentException()
	
	def _get_urls_from_files(self, _files):
		
		if (_files):
			urls = []
			
			for file in _files:
				if (len(file) > 0 and os.path.exists(file)):
					self.logger.print_debug("Extracting URLs from {:s}.".format(file))
					file_urls = []
					if (os.path.isdir(file)):
						file_urls = self._get_urls_from_dir(file)
					elif(os.path.isfile(file)):
						file_urls = self._get_urls_from_file(file)
					urls = urls + file_urls
				else:
					self.logger.print_error(ERR_FILE_NOT_FOUND.format(file))
			return urls
		else:
			raise NullOrEmptyArgumentException()	
	
	def _get_urls_from_file(self, _file):
		if (_file and len(_file) > 0):
			if (os.path.exists(_file)):
				with open(_file, "r") as f:
					contents = f.read().lower().strip()
				
				urls = []
				if (len(contents) > 0):
					found_urls = re.findall(LocalHunter.DefaultUrlRE, contents)
					for found_url in found_urls:
						vx_url = found_url[0]
						vx_file = vx_url.split("/")[-1]						
						vx_ext = vx_file.split('.')[-1]
						#if (not "virustotal" in found_url and vx_ext in self.extensions):
						self.logger.print_debug("\t>> {:s}".format(vx_url))
						urls.append(vx_url.replace("hxxp", "http"))
				return urls
			else:
				raise FileNotFoundException(_file)
		else:
			raise NullOrEmptyArgumentException()
				
	def get_urls_from_files(self, _files):
		urls = self._get_urls_from_files(_files)
		print(urls)
		return urls
		
				
	def get_new_urls_since(self, _date, _max=150):
		urls = []
		urls = self._get_urls_from_files(self.files)
		return urls