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
ERR_FAILED_PARSE_MALCODE=	"Failed to parse MalC0de feed : '{s}'."
ERR_FAILED_DOWNLOAD		=	"Failed to download file '{:s}': {:s}"
MSG_INFO_DOWNLOADING	=	"Downloading {:s} from {:s}."
ERR_FILE_NO_CONTENTS	=	"No contents found in '{:s}'."
MSG_INFO_CONNECTING 	=	"Connecting to '{:s}'..."
MSG_INFO_NB_ENTRIES		=	"{:d} new entries found."
MSG_WARN_NB_ENTRIES		=	"Considering only {:d} entries."
MSG_INFO_NEXT_RUN		=	"Next run: {:%H:%M:%S}"
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Classes
class Hunter(threading.Thread):

	DefaultHuntInterval = 60
	HuntedExtensions = ["exe", "scr", "doc", "pdf", "apk", "jar", "docx", "zip"]

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
				vx_src_file = vx_url.split("/")[-1]						
				vx_in_pit = [ f for f in os.listdir(self.pit) if os.path.isfile(f) ]
				if (not vx_src_file in vx_in_pit):
					vx_dst_file = os.path.join(self.pit, vx_src_file)
					self.logger.print_info(MSG_INFO_DOWNLOADING.format(vx_src_file, vx_url))
					try:
						urllib.urlretrieve (vx_url, vx_dst_file)
					except Exception as e:
						self.logger.print_error(ERR_FAILED_DOWNLOAD.format(vx_src_file, e.message))
						
			self.next_hunt = datetime.now() + timedelta(seconds=Hunter.DefaultHuntInterval)
			self.logger.print_info(MSG_INFO_NEXT_RUN.format(self.next_hunt))
			#DEBUG:
			self.is_hunting = False
			time.sleep(Hunter.DefaultHuntInterval)
			
		self.logger.print_warning("Hunt completed. Thread is terminated.")
		
class MalcodeHunter(Hunter):

	URL = 'http://malc0de.com/rss/'
	URL_MARKER = "URL:"
	
	def __init__(self, _pit, _extensions = [], _logger=None):
		super(MalcodeHunter, self).__init__(_pit, _extensions, _logger)	
		self.last_entry = ""
	
	def get_new_urls_since(self, _date, _max=150):
		urls = []
		
		self.logger.print_info(MSG_INFO_CONNECTING.format(MalcodeHunter.URL))
		malcode_rss = feedparser.parse(MalcodeHunter.URL)
		nb_entries = len(malcode_rss.entries)
		self.logger.print_info(MSG_INFO_NB_ENTRIES.format(nb_entries))				
		if (nb_entries > _max):
			nb_entries = _max
			self.logger.print_warning(MSG_WARN_NB_ENTRIES.format(nb_entries))
		
		for i in range(0, nb_entries):
			post = malcode_rss.entries[i]
			#if (post == self.last_entry):
			#	break
			#self.last_entry = post
			
			desc = post.summary
			
			desc_items = desc.split(",")
			if (len(desc_items) == 5):
				if (MalcodeHunter.URL_MARKER in desc_items[0]):
					vx_url = "http://{:s}".format(desc_items[0].split(":")[1].strip())
											
					vx_file = vx_url.split("/")[-1]						
					vx_ext = vx_file.split('.')[-1]
					if (len(vx_ext) > 5):
						vx_ext = ""

					if (vx_ext in self.extensions):
						urls.append(vx_url)
			else:
				raise Exception(ERR_FAILED_PARSE_MALCODE.format(desc))

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
					if (not "virustotal" in url and vx_ext in self.extensions):
						self.logger.print_debug("\t>> {:s}...".format(url))
						urls.append(url.replace("hxxp", "http"))
			else:
				self.logger.print_error(ERR_FILE_NO_CONTENTS.format(file))
		return urls