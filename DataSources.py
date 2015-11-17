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
import os.path
import shutil
import simplejson
import feedparser

from Logger import Logger
from Virus import Virus
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Globals and Constants
ERR_INVALID_DEST_DIR	=	"Invalid destination folder: '{:s}'."
MSG_INFO_CONNECTING 	=	"Connecting to '{:s}'..."
MSG_INFO_ANALYZING		=	"Analyzing '{:s}' ..."
MSG_INFO_NB_ENTRIES		=	"{:d} new entries found."
MSG_WARN_NB_ENTRIES		=	"Considering only {:d} entries."

ERR_NULL_OR_EMPTY		=	"Value for variable '{:s}' cannot be null or empty."

META_ERROR_INVALID_SRC	=	"Invalid source: '{:s}'."
META_ERROR_NO_METADATA	=	"No metadata found for malware '{:s}'."

AV_AVAST		=	"Avast"
AV_AVG			=	"AVG"
AV_AVIRA		=	"Avira"
AV_BITDEFENDER	=	"BitDefender"
AV_CLAM			=	"ClamAV"
AV_FORTINET		=	"Fortinet"
AV_COMODO		=	"Comodo"
AV_FSECURE		=	"F-Secure"
AV_GDATA		=	"GData"
AV_MALBYTES		=	"MalwareBytes"
AV_MCAFEE		=	"McAfee"
AV_PANDA		=	"Panda"
AV_SOPHOS		=	"Sophos"
AV_ESET			=	"ESET"
AV_SYMANTEC		=	"Symantec"
AV_TRENDMICRO	=	"Trend Micro"
AV_MICROSOFT	=	"Microsoft"
AV_KASPERSKY	=	"Kaspersky"
AV_BAIDU		=	"Baidu-International"

#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Classes

class Analyzer(threading.Thread):

	def __init__(self, _pit, _logger=None):
		threading.Thread.__init__(self)
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		
		if (_pit and os.path.isdir(_pit)):
			self.pit = _pit
		else:
			raise Exception(ERR_INVALID_DEST_DIR.format(_dst))
		
	def stop_analysis():
		self.analyze = False
		
	def run(self):
	
		vt_source = VirusTotalSource()
	
		while (self.analyze):
			vx_in_pit = [ os.path.join(self.pit, f) for f in os.listdir(self.pit) if os.path.isfile(os.path.join(self.pit, f)) ]
			if (len(vx_in_pit) > 0):
				for vx_file in vx_in_pit:
					self.logger.print_info(MSG_INFO_ANALYZING.format(vx_file))
					vx = Virus()
					vx.add_file(vx_file)
					vx_data = vt_source.retrieve_metadata(vx)
					
			time.delay(300)
	

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

	def __init__(self, _api=PARAM_APIKEY):
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
				