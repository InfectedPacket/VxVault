#!/usr/bin/env python
# -*- coding: latin-1 -*-
#//////////////////////////////////////////////////////////////////////////////
#█▀▀▀▀█▀▀▀▀▀██▀▀▀▀██▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀▀▓▒▀▀▀▀▀▀▀▀▀▀█▓▀ ▀▀▀██▀▀▀▀▀▀▀▀▀▓▓▀▀▀▀▀▀▀▀▀
#▌▄██▌ ▄▓██▄ ▀▄█▓▄▐ ▄▓█▓▓▀█ ▄▓██▀▓██▓▄ ▌▄█▓█▀███▓▄ ▌▄█▓█ ▀ ▄▓██▀▓██▓▄ ▄█▓█▀███▄
#▌▀▓█▓▐▓██▓▓█ ▐▓█▓▌▐▓███▌■ ▒▓██▌ ▓██▓▌▐▓▒█▌▄ ▓██▓▌ ▐▓▒█▌▐ ▒▓██▌  ▓██▓▌▓▒█▌ ▓█▓▌
#▐▓▄▄▌░▓▓█▓▐▓▌ █▓▓▌░▓▓█▓▄▄ ▓▓██▓▄▄▓█▓▓▌░▓█▓ █ ▓█▓▓▌░▓█▓ ▒ ▓▓██▓▄▄▓█▓▓▌▓█▓ ░ ▓█▓
#▐▓▓█▌▓▓▓█▌ █▓▐██▓▌▐▓▒▓▌ ▄ ▐░▓█▌▄ ▀▀▀ ▐▓▓▓ ▐▌ ▀▀▀  ▐▓▓▓▄▄ ▐░▓█▌ ▄ ▀▀▀ ▓▓▓ ░ ██▓
#▐▓▓▓█▐▓▒██ ██▓▓▓▌▐▓▓██  █▌▐▓▓▒▌▐ ███░▌▐▓▓▒▌▐ ███░▌ ▐▓▓▒▌ ▐▓▓▒▌▀ ███░▌▓▓▒▌ ███░
# ▒▓▓█▌▒▓▓█▌ ▐▓█▒▒  ▒▓██▌▐█ ▒▓▓█ ▐█▓▒▒ ▒▒▓█  ▐█▓▒▒  ▒▒▓█ ▓▌▒▓▓█ ▐█▓▒▒ ▒▒▓█ ▐█▓▒
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
import subprocess
#//////////////////////////////////////////////////////////////////////////////
DEFAULT_WIN_7ZIP_PATH = "C:\\Program Files\\7-Zip\\7z.exe"
DEFAULT_LINUX_7ZIP_PATH = "/usr/bin/7z"
ERR_7Z_NOTFOUND = "Could not find archiving program: {:s}."
EXTENSION_7Z		= ".7z"
#//////////////////////////////////////////////////////////////////////////////

class Archiver(object):

	def __init__(self, _archiver, _password , _logger=None):
		#**********************************************************************
		# Creates a new logger object.
		#**********************************************************************
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger	

		if (len(_archiver) > 0 and os.path.isfile(_archiver)):
			self.archiver = _archiver
		else:
			raise Exception("Invalid path to archiver program: '{:s}'.".format(_archiver))
				
		self.password = _password

	@abc.abstractmethod
	def archive(self, _vx, _dst_path):
		return
		
class SevenZipArchiver(Archiver):

	ArchiveExtension = EXTENSION_7Z
	DefaultWindows7ZipPath = DEFAULT_WIN_7ZIP_PATH
	DefaultLinux7ZipPath = DEFAULT_LINUX_7ZIP_PATH

	def __init__(self, 
		_archiver=DefaultWindows7ZipPath, 
		_password="", 
		_logger=None):
		super(SevenZipArchiver, self).__init__(_archiver, _password, _logger)	
		
	def get_extension(self):
		return SevenZipArchiver.ArchiveExtension
		
	def archive(self, _vx, _dst_file):
		vx_arch_files = _vx.get_files()
		vx_arch_file = _dst_file
		
		self.logger.print_debug("Saving archive to '{:s}'.".format(vx_arch_file))
		print("Saving archive to '{:s}'.".format(vx_arch_file))
		result = subprocess.call(
			[self.archiver, "a", "-t7z", "-p{:s}".format(self.password), "-y", vx_arch_file] +
			vx_arch_files, shell=False)
		
		if (result != 0):
			raise Exception("Error while creating the archive.")
		
		return vx_arch_file