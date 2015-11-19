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
import shutil
import os.path
import threading
from datetime import datetime

from Virus import Virus
from DataSources import *
#//////////////////////////////////////////////////////////
# Globals and Constants
ERR_INVALID_DEST_DIR	=	"Invalid destination folder: '{:s}'."
ERR_NULL_DATA_SOURCE	=	"Malware data source cannot be null."
MSG_INFO_NEXT_RUN		=	"Next run: {:%H:%M:%S}"
MSG_INFO_ANALYZING		=	"Analyzing '{:s}' ..."
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
class Analyzer(threading.Thread):

	DefaultWaitDelay = 3

	def __init__(self, _vxdata, _pit, _logger=None):
		threading.Thread.__init__(self)
		self.name = "vx_pit_analyzer"
		self.analyze = False
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		
		if (_pit and os.path.isdir(_pit)):
			self.pit = _pit
		else:
			raise Exception(ERR_INVALID_DEST_DIR.format(_dst))
		
		if (_vxdata != None):
			self.datasource = _vxdata
		else:
			raise Exception(ERR_NULL_DATA_SOURCE)
		
	def stop_analysis(self):
		self.analyze = False
		
	def run(self):
		self.analyze = True
		while (self.analyze):
			vx_in_pit = [ os.path.join(self.pit, f) for f in os.listdir(self.pit) if os.path.isfile(os.path.join(self.pit, f)) ]
			if (len(vx_in_pit) > 0):
				for vx_file in vx_in_pit:
					self.logger.print_info(MSG_INFO_ANALYZING.format(vx_file))
					vx = Virus()
					vx.add_file(vx_file)
					try:
						vx_dst_file = ""
						self.datasource.retrieve_metadata(vx)
						vxdata = vx.get_antiviral_results()
						
						if (vxdata and len(vxdata) > 0):
							print(vxdata)
							self.logger.print_debug("File:{:s}:".format(vx_file))
							for (av, detection) in vxdata.iteritems():
								self.logger.print_debug("\t{:s}:{:s}".format(av, detection))
								if (detection != "None"):
									vx_dst_file = detection
							
							if (len(vx_dst_file) > 0):					
								if vx.is_detected_by(AV_KASPERSKY):
									vx_dst_file = vx.get_detection_by(AV_KASPERSKY)
								elif vx.is_detected_by(AV_BAIDU):
									vx_dst_file = vx.get_detection_by(AV_BAIDU)
								elif vx.is_detected_by(AV_CLAM):
									vx_dst_file = vx.get_detection_by(AV_CLAM)
								elif vx.is_detected_by(AV_SYMANTEC):
									vx_dst_file = vx.get_detection_by(AV_SYMANTEC)
								#TODO: move file
								self.logger.print_debug("Saving malware as '{:s}'...".format(vx_dst_file))	
							else:
								self.logger.print_warning("No detection for file '{:s}'.".format(vx_file))
							

						else:
							self.logger.print_warning("No data retrieved for '{:s}'.".format(vx_file))
					except Exception as e:
						self.logger.print_error("Could not retrieve data for '{:s}': {:s}".format(vx_file, e.message))
						
					self.next_run = self.datasource.get_next_allowed_request()
					self.logger.print_debug(MSG_INFO_NEXT_RUN.format(self.next_run))
					while (datetime.now() < self.next_run and self.analyze):
						time.sleep(Analyzer.DefaultWaitDelay)
	
					if (not self.analyze):
						break
						
		self.logger.print_warning("Analysis completed. Thread '{:s}' terminated.".format(self.name))