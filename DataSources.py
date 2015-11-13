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
import urllib
import urllib2
import os.path
import simplejson
import feedparser

from Logger import Logger
from Virus import Virus
#//////////////////////////////////////////////////////////

MSG_INFO_CONNECTING 	=	"Connecting to '{:s}'..."
MSG_INFO_NB_ENTRIES		=	"{:d} new entries found."
MSG_WARN_NB_ENTRIES		=	"Considering only {:d} entries."

ERR_NULL_OR_EMPTY		=	"Value for variable '{:s}' cannot be null or empty."
ERR_INVALID_DEST_DIR	=	"Invalid destination folder: '{:s}'."
ERR_FAILED_PARSE_MALCODE=	"Failed to parse MalC0de feed : '{s}'."
META_ERROR_INVALID_SRC	=	"Invalid source: '{:s}'."
META_ERROR_NO_METADATA	=	"No metadata found for malware '{:s}'."

#//////////////////////////////////////////////////////////
# Classes
class DataSource(object):
	__metaclass__ = abc.ABCMeta
	
	def __init__(self, _source, _parameters = {}):
		self.set_source(_source)
		self.set_parameters(_parameters)
			
	def set_source(self, _source):
		if (not _source):
			raise Exception(ERR_NULL_OR_EMPTY.format("source"))

		self.source = _source
		
	def get_source(self):
		return _source
		
	def add_parameter(self, _param, _value=""):
		if (not _param):
			raise Exception(ERR_NULL_OR_EMPTY.format("param"))
		
		self.parameters[_param] = _value
		
	def get_param_value(self, _param):
		if (not _param):
			raise Exception(ERR_NULL_OR_EMPTY.format("param"))
		
		return self.parameters[_param]
	
	def set_parameters(self, _params = {}):
		self.parameters = _params
		
	def get_parameters(self):
		return self.parameters

	@abc.abstractmethod
	def retrieve_metadata(self, _vx):
		return

		
class OnlineSource(DataSource):
	__metaclass__ = abc.ABCMeta
	
	def __init__(self, _source, _parameters = {}):
		super(OnlineSource, self).__init__(_source, parameters)
	
	@abc.abstractmethod
	def retrieve_metadata(self, _vx):
		return
	
class VirusTotalSource(DataSource):

	PARAM_RSRC = "resource"
	PARAM_APIKEY = "apikey"
	URL_VT_REPORT = "https://www.virustotal.com/vtapi/v2/file/report"

	def __init__(self, _api):
		super(VirusTotalSource, self).__init__(VirusTotalSource.URL_VT_REPORT)
		self.add_parameter(VirusTotalSource.PARAM_APIKEY, _api)

	def retrieve_metadata(self, _vx):
		if (_vx):
			vx_files = _vx.get_files()
			if (len(vx_files) > 0):
				vx_md5 = _vx.md5()[vx_files[0]]
				request_params = {VirusTotalSource.PARAM_RSRC: vx_md5, 
									VirusTotalSource.PARAM_APIKEY: self.get_param_value(VirusTotalSource.PARAM_APIKEY)}
				data = urllib.urlencode(request_params)
				req = urllib2.Request(self.source, data)
				response = urllib2.urlopen(req)
				json = response.read()
				vx_data = simplejson.loads(json)
				vx_scans = vx_data.get("scans", {})
				if (vx_data.get("response_code", {}) != 1 or len(vx_scans) <= 0):
					raise Exception(META_ERROR_NO_METADATA.format(vx_files[0]))
					
				scans = {}
				for scan in vx_scans:
					scans[scan] = vx_scans[scan][u'result']
					#print("{:s}:{:s}".format(scan, vx_scans[scan][u'result']))
				_vx.set_antiviral_results(scans)
				
class MalCodeRssSource(object):

	URL = 'http://malc0de.com/rss/'
	URL_MARKER = "URL:"
	
	def __init__(self, _extensions = [], _logger=None):
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		self.allowed_extensions = _extensions
		
	def get_new_urls_since(self, _date, _max=50):
		urls = {}
		if (_dst and os.path.isdir(_dst)):
			self.logger.print_info(MSG_INFO_CONNECTING.format(MalCodeRssSource.URL))
			malcode_rss = feedparser.parse(MalCodeRssSource.URL)
			nb_entries = len(malcode_rss.entries)
			self.logger.print_info(MSG_INFO_NB_ENTRIES.format(nb_entries))				
			if (nb_entries > _max):
				nb_entries = _max
				self.logger.print_warning(MSG_WARN_NB_ENTRIES.format(nb_entries))
			
			for i in range(0, nb_entries):
				post = malcode_rss.entries[i]
				desc = post.summary
				
				desc_items = desc.split(",")
				if (len(desc_items) == 5):
					if (MalCodeRssSource.URL_MARKER in desc_items[0]):
						vx_url = desc_items[0].split(":")[1]
						vx_file = vx_url.split("/")[-1]						
						vx_ext = vx_file.split('.')[-1]
						if (len(vx_ext) > 5):
							vx_ext = ""
						vx_md5 = desc_items[4].split(":")[1]
						display_file = vx_file
						if (len(vx_file) > 10):
							display_file = "{:s}(...).{:s}".format(vx_file[0:8], vx_ext)
						self.logger.print_info("New! {:s}:\t{:s}".format(vx_md5, display_file))
						if (vx_ext in self.allowed_extensions):
							urls[vx_md5] = vx_url

				else:
					raise Exception(ERR_FAILED_PARSE_MALCODE.format(desc))
		else:
			raise Exception(ERR_INVALID_DEST_DIR.format(_dst))
		return urls