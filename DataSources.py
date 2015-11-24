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
from datetime import datetime, timedelta
#
from Logger import Logger
from Virus import Virus
#//////////////////////////////////////////////////////////////////////////////
#
#//////////////////////////////////////////////////////////////////////////////
# Globals and Constants
ERR_INVALID_DEST_DIR	=	"Invalid destination folder: '{:s}'."
MSG_INFO_CONNECTING 	=	"Connecting to '{:s}'..."
MSG_INFO_ANALYZING		=	"Analyzing '{:s}' ..."
MSG_INFO_NB_ENTRIES		=	"{:d} new entries found."
MSG_WARN_NB_ENTRIES		=	"Considering only {:d} entries."
INFO_GET_INDENTS		=	"Retrieving report for '{:s}' ({:s})."
INFO_VT_SUCCESS			=	"Successfully retrieved report from VirusTotal."
#
ERR_NULL_OR_EMPTY		=	"Value for variable '{:s}' cannot be null or empty."
ERR_FAILED_VT			=	"Failed to retrieve scan information."
ERR_NULL_VX_OBJ			=	"Provided Virus object is null."
#
META_ERROR_INVALID_SRC	=	"Invalid source: '{:s}'."
META_ERROR_NO_METADATA	=	"No metadata found for malware '{:s}'."
#
#//////////////////////////////////////////////////////////////////////////////
#
#//////////////////////////////////////////////////////////////////////////////
# Classes
class VxDataSource(object):
	__metaclass__ = abc.ABCMeta
	
	def __init__(self, _source, _parameters = {}, _logger=None):
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
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
	def get_next_allowed_request(self):
		return
		
	@abc.abstractmethod
	def retrieve_metadata(self, _vx):
		return


class VirusTotalSource(VxDataSource):

	# Parameter for the request to VT specifying the 
	# identifier sent.
	PARAM_RSRC = "resource"
	
	# Parameter for the request to VT specifying the 
	# API key.
	PARAM_APIKEY = "apikey"
	
	# URL to the API of VirusTotal
	URL_VT_REPORT = "https://www.virustotal.com/vtapi/v2/file/report"

	def __init__(self, _apikey, _logger=None):
		super(VirusTotalSource, self).__init__(VirusTotalSource.URL_VT_REPORT, 
			_logger=_logger)
		self.add_parameter(VirusTotalSource.PARAM_APIKEY, _apikey)

	def get_next_allowed_request(self):
		"""Retrieves the timing of the next allowed request by
		the data source.

		This function provides a 'datetime' object which specifies
		the time ater which the Analyzer can sent another request. This
		is to prevent lockdown of the API key due to request limitations.

		Args:
			None.

		Returns:
			A datetime object with the time of the next allowed request.

		Raises:
			None.
		"""
		#**********************************************************************
		# Only 4 requests a minute are allowed on VT for public API keys.
		#**********************************************************************
		delay = 15 # Every 15 seconds
		#**********************************************************************
		# Provides the time of the next authorized request
		# 2 seconds are added to add some leeway.
		#**********************************************************************
		return datetime.now() + timedelta(seconds=delay+2)
		
	def retrieve_metadata(self, _vx):
		if (_vx):
			vx_files = _vx.get_files()
			if (len(vx_files) > 0):
				vx_md5 = _vx.md5()
				self.logger.print_debug(INFO_GET_INDENTS.format(vx_files[0], vx_md5))
				request_params = {VirusTotalSource.PARAM_RSRC: vx_md5, 
									VirusTotalSource.PARAM_APIKEY: self.get_param_value(VirusTotalSource.PARAM_APIKEY)}
				data = urllib.urlencode(request_params)
				req = urllib2.Request(self.source, data)
				response = urllib2.urlopen(req)
				json = response.read()
				vx_data = simplejson.loads(json)
				vx_scans = vx_data.get("scans", {})
				if (vx_data.get("response_code", {}) != 1 or len(vx_scans) <= 0):
					self.logger.print_error(ERR_FAILED_VT)
					raise Exception(META_ERROR_NO_METADATA.format(vx_files[0]))
				self.logger.print_success(INFO_VT_SUCCESS)
				
				scans = {}
				for scan in vx_scans:
					ident = vx_scans[scan][u'result']
					if (ident and ident.lower().strip() != Virus.NOT_DETECTED):
						_vx.add_ident(scan, ident)
		else:
			raise Exception(ERR_NULL_VX_OBJ)