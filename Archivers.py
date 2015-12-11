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
#
from VaultExceptions import *
#
#//////////////////////////////////////////////////////////////////////////////
#
# Constants
#
DEFAULT_WIN_7ZIP_PATH = "C:\\Program Files\\7-Zip\\7z.exe"
DEFAULT_LINUX_7ZIP_PATH = "/usr/bin/7z"
EXTENSION_7Z		= "7z"
#
#//////////////////////////////////////////////////////////////////////////////

class Archiver(object):

	def __init__(self, _archiver, _password , _logger=None):
		#**********************************************************************
		# Creates a new logger object.
		#**********************************************************************
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger	

		#**********************************************************************
		# Verifies the path to the archiver is valid
		#**********************************************************************
		if (len(_archiver) > 0 and os.path.isfile(_archiver)):
			self.archiver = _archiver
		else:
			raise FileNotFoundException(_archiver)
				
		#**********************************************************************
		# Sets the password to use for the generated archives.
		#**********************************************************************
		self.password = _password

	@abc.abstractmethod
	def archive(self, _vx, _dst_path):
		return
		
	@abc.abstractmethod
	def get_extension(self):
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
		
	def archive(self, _vx, _dstpath):
		""" Creates a 7zip archive file containing all files contained in the
		provided Virus object at the given destination path.
		
		This function will archive the files contained in the Virus object into a
		7zip archive. The archive will be created at the provided destination.
		
		Args:
			_vx: The virus object containing the files to be archived.
			
		Returns:
			None.
			
		Raises:
			ArchiveCreationException; if an error occurs while creating
			the archive.
			NullOrEmptyArgumentException; if one or more of the provided
			argument is null or empty.
		"""
		
		if (_vx and _dstpath and len(_dstpath) > 0):
		
			vx_arch_files = [ f.get_absolute() for f in _vx.get_files()]
			vx_arch_file = os.path.join(_dstpath, _vx.generate_archive_name(self.get_extension()))
			
			#**********************************************************************
			# Verifies if the Virus objects contains file to be
			# archive.
			#**********************************************************************
			if (len(vx_arch_files) > 0):
				#******************************************************************
				# Calls 7zip from the system to create the archive.
				#******************************************************************
				result = subprocess.call(
					[self.archiver, "a", "-t7z", "-p{:s}".format(self.password), "-y", vx_arch_file] +
					vx_arch_files, shell=False)
				self.logger.print_success(INFO_ARCHIVE_CREATED.format(vx_arch_file))
			else:
				raise ArchiveCreationException(ERR_VIRUS_NO_FILE)
			
			if (result != 0):
				raise ArchiveCreationException()
			#**********************************************************************
			# Sets the archive created as one of the properties
			# of the Virus object.
			#**********************************************************************
			_vx.set_archive(vx_arch_file)
			return vx_arch_file
		else:
			raise NullOrEmptyArgumentException()