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
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Globals and Constants
ERR_INVALID_DEST_DIR	=	"Invalid directory: '{:s}'."
ERR_FAILED_PARSE_MALCODE=	"Failed to parse MalC0de feed : '{:s}'."
ERR_FAILED_DOWNLOAD		=	u"Failed to download file '{:s}': {:s}"
MSG_INFO_DOWNLOADING	=	u"Downloading {:s} from {:s}."
ERR_FILE_NO_CONTENTS	=	"No contents found in '{:s}'."
MSG_INFO_CONNECTING 	=	"Connecting to '{:s}'..."
MSG_INFO_NB_ENTRIES		=	"{:d} new entries found."
MSG_WARN_NB_ENTRIES		=	"Considering only {:d} entries."
MSG_INFO_NEXT_RUN		=	"Next run: {:%H:%M:%S}"
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Classes
class Hunter(threading.Thread):

	DefaultHuntWait = 1
	DefaultHuntInterval = 3600
	HuntedExtensions = ["exe", "dll", "scr", "doc", "pdf", "apk", "jar", "docx", "zip"]

	def __init__(self, _pit, _extensions = HuntedExtensions, _logger=None):
		threading.Thread.__init__(self)
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger	
		self.name="vx-hunter"
		self.is_hunting = True
		if (_pit and os.path.isdir(_pit)):
			self.pit = _pit
		else:
			raise Exception(ERR_INVALID_DEST_DIR.format(_dst))
		
		self.extensions = _extensions

	
	def stop_hunting(self):
		self.is_hunting = False;
	
	@abc.abstractmethod
	def get_new_urls_since(self, _date, _max=150):
		return
	
	def run(self):
	
		while (self.is_hunting):
			new_targets = self.get_new_urls_since(datetime.now())
			for vx_url in new_targets:
				#vx_url = urllib.unquote(vx_url).decode('utf8') 
				vx_url = urllib.unquote(vx_url)
				vx_src_file = vx_url.split("/")[-1]						
				vx_in_pit = [ f for f in os.listdir(self.pit) if os.path.isfile(f) ]
				# TODO:
				# [ ] Need to change to DB, files are deleted from the
				# pit now.
				if (not vx_src_file in vx_in_pit):
					vx_dst_file = os.path.join(self.pit, vx_src_file)
					if u"?" in vx_src_file:
						vx_request = vx_dst_file.split(u"?")
						vx_dst_file = vx_request[0]

					self.logger.print_info(MSG_INFO_DOWNLOADING.format(vx_src_file, vx_url))
					try:
						urllib.urlretrieve (vx_url, vx_dst_file)
					except Exception as e:
						self.logger.print_error(ERR_FAILED_DOWNLOAD.format(vx_src_file, e.message))
				else:
					self.logger.print_info(u"File '{:s}' already exists in pit.".format(vx_src_file))
			self.next_hunt = datetime.now() + timedelta(seconds=Hunter.DefaultHuntInterval)
			self.logger.print_info(MSG_INFO_NEXT_RUN.format(self.next_hunt))
			
			while (datetime.now() < self.next_hunt and self.is_hunting):
				if self.is_hunting == True:
					time.sleep(Hunter.DefaultHuntWait)
			
		self.logger.print_warning("Hunt completed. Thread '{:s}' is terminated.".format(self.name))
		
class MalcodeHunter(Hunter):

	THREAD_NAME = "vx-hunter-malcode"
	URL = 'http://malc0de.com/rss/'
	URL_MARKER = "URL:"
	
	def __init__(self, _pit, _extensions = Hunter.HuntedExtensions, _logger=None):
		super(MalcodeHunter, self).__init__(_pit, _extensions, _logger)	
		self.name=MalcodeHunter.THREAD_NAME
		self.last_entry = u""
	
	def get_new_urls_since(self, _date, _max=150):
		urls = []
		
		#TODO:
		# [ ] Move at the beginning of the file.
		HTTP_URL_FORMAT = u"http://{:s}"		
		INFO_NBENTRIES_FOUND = u"New entries found: {:d}."
		MalcodeRssSummarySeparator = u":"
		MalcodeRssContentsSeparator = u","
		
		self.logger.print_debug(MSG_INFO_CONNECTING.format(MalcodeHunter.URL))
		#
		# Retrieve the RSS feed from Malcode:
		#
		malcode_rss = feedparser.parse(MalcodeHunter.URL)

		#
		# Start processing entries if any where found.
		#
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
			# If new entries are found, start downloading them
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
					
					desc_items = desc.split(MalcodeRssContentsSeparator)
					url_data = desc_items[0]
					#self.logger.print_debug("New url found: '{:s}'.".format(url_data))
					if (len(desc_items) == 5):
						if (MalcodeHunter.URL_MARKER in url_data):
							if (MalcodeRssSummarySeparator in url_data):
								url_data = url_data.split(MalcodeRssSummarySeparator)[1]
							url_data = url_data.strip()
							
							if (len(url_data) > 0):
								vx_url = HTTP_URL_FORMAT.format(url_data)
														
								vx_file = vx_url.split("/")[-1]	
								if (u"?" in vx_file):
									tmp_file = vx_file.split(u"?")
									vx_file = tmp_file[0]
							
								vx_ext = vx_file.split('.')[-1]
								if (len(vx_ext) > 5):
									vx_ext = ""

								if (vx_ext in self.extensions):
									#self.logger.print_debug("\tNew: {:s}.".format(str(vx_url)))
									urls.append(vx_url)
								else:
									self.logger.print_debug(u"Ignoring url. Extension '{:s}' is not in download list.".format(vx_ext))
						else:
							self.logger.print_warning(u"Could not find URL in post: \n{:s}".format(desc))
					else:
						#raise Exception(ERR_FAILED_PARSE_MALCODE.format(desc))
						self.logger.print_warning(ERR_FAILED_PARSE_MALCODE.format(desc))
			else:
				self.logger.print_warning(u"No new entries found on malcode.")
		return urls	
	

		
class LocalHunter(Hunter):

	def __init__(self, _pit, _dir, _extensions = [], _logger=None):
		super(LocalHunter, self).__init__(_pit, _extensions, _logger)
		self.dir = _dir
		
	def get_new_urls_since(self, _date, _max=150):
		urls = []
		self.logger.print_info(MSG_INFO_CONNECTING.format(self.dir))
		
		local_files = [ os.path.join(self.dir, f) for f in os.listdir(self.dir) if not os.path.isfile(f) ]
		
		for file in local_files:
			self.logger.print_debug("Processing '{:s}'...".format(file))
			with open(file, "r") as f:
				contents = f.read().lower()
			if (len(contents) > 0):
				found_urls = re.findall(r'(h(tt|xx)ps?://[^\s]+)', contents)
				for found_url in found_urls:
					vx_url = found_url[0]
					vx_file = vx_url.split("/")[-1]						
					vx_ext = vx_file.split('.')[-1]
					if (not "virustotal" in found_url and vx_ext in self.extensions):
						self.logger.print_debug("\t>> {:s}...".format(url))
						urls.append(url.replace("hxxp", "http"))
			else:
				self.logger.print_error(ERR_FILE_NO_CONTENTS.format(file))
		return urls