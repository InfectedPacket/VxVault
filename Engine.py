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

__version_info__ = ('0','1','0')
__version__ = '.'.join(__version_info__)


#//////////////////////////////////////////////////////////
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
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Constants
ENGINE_ERROR_INVALID_FILE	=	"Invalid file: {:s}."
ENGINE_ERROR_ARCHIVER_404	=	"Could not find archiving program: {:s}."
ENGINE_ERROR_UNKNOWN_TYPE	=	"Unknown file type: {:s}."
ENGINE_ERROR_NO_METADATA	=	"No metadata found for malware '{:s}'."

DS_VIRUS_TOTAL = "VirusTotal"

DEFAULT_DATA_SOURCE = DS_VIRUS_TOTAL

#//////////////////////////////////////////////////////////

class Engine(object):

	MaxActiveAnalyzers = 1

	def __init__(self, _base, _vtapi, _logger=None):
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		self.data_sources = {}
		self.data_sources[DS_VIRUS_TOTAL] = VirusTotalSource(_vtapi)
		self.active_hunters = []
		self.active_analyzers = []
		self.vxvault = Vault(_base, self.logger)
		
	def __repr__(self):
		return "<VxVault Engine {:s}>".format(__version__)
		
	def is_windows(self):
		return ("win" in platform.system().lower())

	def set_archiver(self, _program):
		if (os.path.isfile(_program)):
			self.archiver = _program
		else:
			raise Exception(ENGINE_ERROR_ARCHIVER_404.format(_program))
		
	def get_archiver(self):
		return self.archiver		
		
	def create_vault(self, _base):
		self.vxvault = Vault(_base, self.logger)
		self.vxvault.file_system.create_filesystem()	
		
	def load_vault(self, _base):
		self.vxvault = Vault(_base, self.logger)
		
	def generate_vx(self, _file, _name=Virus.DEFAULT_VX_NAME):
		if os.path.isfile(_file):
			vx = self.generate_vx_from_file(_file, _name)
		elif os.path.isdir(_file):
			vx = self.generate_vx_from_folder(_file, _name)
		else:
			raise Exception(ENGINE_ERROR_UNKNOWN_TYPE.format(_file))
			
		return vx

	def retrieve_vx_metadata(self, _vx, _datasource=DEFAULT_DATA_SOURCE):
		self.data_sources[_datasource].retrieve_metadata(_vx)

	def generate_vx_from_file(self, _file, _name=Virus.DEFAULT_VX_NAME):
		if not os.path.isfile(_file):
			raise Exception(ENGINE_ERROR_INVALID_FILE.format(_file))

		vx = Virus()
		vx.reset_size()
		vx.set_name(_name)
		vx.add_size(os.path.getsize(_file))
		vx.add_file(_file)
		return vx
		
	def generate_vx_from_folder(self, _folder, _name=Virus.DEFAULT_VX_NAME):
		vx = Virus()
		vx.reset_size()
		vx.set_name(_name)
		files = os.listdir(_folder)
		for file in files:
			vx.add_size(os.path.getsize(file))
			vx.add_file(file)
		return vx				
		
	def archive_virus(self, _vxfile, _destination, _password):
		compression_program = self.get_archiver()
		vx_archive = _vxfile.archive(
			_destination, 
			_password, 
			compression_program)
		return vx_archive		
		
	def gather_vx_from_malcode(self):
		vx_pit = self.vxvault.get_pit()
		vx_hunter = MalcodeHunter(_pit=vx_pit, _logger=self.logger)
		self.active_hunters.append(vx_hunter)
		vx_hunter.start()
		
	def gather_vx_from_local_files(self, _datadir):
		vx_pit = self.vxvault.get_pit()
		vx_hunter = LocalHunter(_pit=vx_pit, _dir=_datadir, _logger=self.logger)
		self.active_hunters.append(vx_hunter)
		vx_hunter.start()
		
	def active_analyzers_count(self):
		return len(self.active_analyzers)
		
	def start_vt_analyzer(self):
		if (len(self.active_analyzers) < Engine.MaxActiveAnalyzers):
			vx_pit = self.vxvault.get_pit()
			vx_data_source = self.data_sources[DS_VIRUS_TOTAL]
			vx_analyzer = Analyzer(_vxdata=vx_data_source, _pit=vx_pit, _logger=self.logger)
			self.active_analyzers.append(vx_analyzer)
			vx_analyzer.start()
		else:
			self.logger.print_warning("Maximum of analyzers reached.")
		
	def stop_hunters(self):
		for vx_hunter in self.active_hunters:
			vx_hunter.stop_hunting()
			vx_hunter.join()
			
	def stop_analyzers(self):
		for vx_analyzer in self.active_analyzers:
			vx_analyzer.stop_analysis()
			vx_analyzer.join()