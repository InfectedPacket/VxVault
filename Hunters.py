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
import abc
import sys
import time
import urllib
import urllib2
import threading
import feedparser
from datetime import datetime
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Globals and Constants
ERR_INVALID_DEST_DIR	=	"Invalid destination folder: '{:s}'."
ERR_FAILED_PARSE_MALCODE=	"Failed to parse MalC0de feed : '{s}'."
MSG_INFO_CONNECTING 	=	"Connecting to '{:s}'..."
MSG_INFO_NB_ENTRIES		=	"{:d} new entries found."
MSG_WARN_NB_ENTRIES		=	"Considering only {:d} entries."
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Classes
class Hunter(threading.Thread):

	DefaultHuntInterval = 3600
	HuntedExtensions = ["exe", "scr", "doc", "pdf", "apk", "jar", "docx", "zip"]

	def __init__(self, _pit, _extensions = HuntedExtensions, _logger=None):
		threading.Thread.__init__(self)
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger	
		self.name="vx-hunter"
		self.hunt = True
		if (_pit and os.path.isdir(_pit)):
			self.pit = _pit
		else:
			raise Exception(ERR_INVALID_DEST_DIR.format(_dst))
		
		self.extensions = _extensions
		
		malcode_area = MalCodeRssSource(_extensions, _logger)
		
		self.areas = [malcode_area]
	
	def stop_hunting(self):
		self.hunt = False;
	
	def run(self):
	
		while (self.hunt):
			for area in self.areas:
				new_targets = area.get_new_urls_since(datetime.now())
				for (md5, vx_url) in new_targets.iteritems():
						vx_src_file = vx_url.split("/")[-1]						
						vx_in_pit = [ f for f in os.listdir(self.pit) if os.path.isfile(f) ]
						if (not vx_src_file in vx_in_pit):
							vx_dst_file = os.path.join(self.pit, vx_src_file)
							self.logger.print_info("Downloading {:s} from {:s}.".format(vx_src_file, vx_url))
							try:
								urllib.urlretrieve (vx_url, vx_dst_file)
							except Exception as e:
								self.logger.print_error("Failed to download file '{:s}': {:s}".format(vx_src_file, e.message))
			self.logger.print_info("Next run in 1 hour.")
			time.sleep(Hunter.DefaultHuntInterval)
			
		self.logger.print_warning("Hunt completed. Thread is terminated.")
		
class MalCodeRssSource(object):

	URL = 'http://malc0de.com/rss/'
	URL_MARKER = "URL:"
	
	def __init__(self, _extensions = [], _logger=None):
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		self.allowed_extensions = _extensions
		self.last_entry = ""
		
	def get_new_urls_since(self, _date, _max=50):
		urls = {}
		
		self.logger.print_info(MSG_INFO_CONNECTING.format(MalCodeRssSource.URL))
		malcode_rss = feedparser.parse(MalCodeRssSource.URL)
		nb_entries = len(malcode_rss.entries)
		self.logger.print_info(MSG_INFO_NB_ENTRIES.format(nb_entries))				
		if (nb_entries > _max):
			nb_entries = _max
			self.logger.print_warning(MSG_WARN_NB_ENTRIES.format(nb_entries))
		
		for i in range(0, nb_entries):
			post = malcode_rss.entries[i]
			if (post == self.last_entry):
				break
			self.last_entry = post
			
			desc = post.summary
			
			desc_items = desc.split(",")
			if (len(desc_items) == 5):
				if (MalCodeRssSource.URL_MARKER in desc_items[0]):
					#vx_url = desc_items[0]
					vx_url = "http://{:s}".format(desc_items[0].split(":")[1].strip())
											
					vx_file = vx_url.split("/")[-1]						
					vx_ext = vx_file.split('.')[-1]
					if (len(vx_ext) > 5):
						vx_ext = ""

					if (vx_ext in self.allowed_extensions):
						vx_md5 = desc_items[4].split(":")[1]
						#display_file = vx_file
						#if (len(vx_file) > 10):
						#	display_file = "{:s}(...).{:s}".format(vx_file[0:8], vx_ext)
						#self.logger.print_info("New! {:s}:\t{:s}".format(vx_md5, display_file))
						urls[vx_md5] = vx_url

			else:
				raise Exception(ERR_FAILED_PARSE_MALCODE.format(desc))

		return urls			