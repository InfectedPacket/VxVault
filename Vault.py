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
# <date>2015-10-25</date>
# <url>https://github.com/infectedpacket</url>

#//////////////////////////////////////////////////////////
# Imports Statements
import os
import sys
import os.path

from Logger import Logger
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Constants
VAULT_ERROR_INVALID_BASE_DIR = "Invalid base directory: '{:s}'."

#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Classes
class Vault(object):

	
	def __init__(self, _base, _name="", _logger=None):
		if _logger == None self.logger = Logger(sys.stdout)
		self.set_name(str(_name))
		self.file_system = FileSystem(_base)
		
	def __repr__(self):
		return "<Vault '{:s}' @{:s}>".format(
			self.get_name(), self.file_system.get_base())
		
	def set_name(self, _name):
		self.name = str(_name)
		

class FileSystem(object):
	SUBFOLDER_WINDOWS 	= "win"
	SUBFOLDER_MSDOS 	= "msdos"
	SUBFOLDER_LINUX 	= "linux"
	SUBFOLDER_UNIX 		= "unix"
	SUBFOLDER_OSX 		= "osx"
	SUBFOLDER_ANDROID	= "android"
	SUBFOLDER_WEB		= "web"
	SUBFOLDER_ANY		= "any"
	SUBFOLDER_OTHERS	= "other"
	
	SUBFOLDER_VIRUS		= "virus"
	SUBFOLDER_WORM		= "worm"
	SUBFOLDER_TROJAN	= "trojan"
	SUBFOLDER_ROOTKIT	= "rootkit"
	SUBFOLDER_EXPLOITKIT= "exploitkit"
	SUBFOLDER_RAT		= "rat"
	SUBFOLDER_WEBSHELL	= "web"
	SUBFOLDER_CRYPTER	= "crypter"
	SUBFOLDER_SPYWARE	= "spyware"
	
	OperatingSystems = [SUBFOLDER_WINDOWS,
						SUBFOLDER_MSDOS,
						SUBFOLDER_LINUX,
						SUBFOLDER_UNIX,
						SUBFOLDER_OSX,
						SUBFOLDER_ANDROID,
						SUBFOLDER_WEB,
						SUBFOLDER_ANY,
						SUBFOLDER_OTHERS]
	MsDosSubFolders = [SUBFOLDER_VIRUS,
						SUBFOLDER_WORM,
						SUBFOLDER_TROJAN]
	LinuxSubFolders = MsDosSubFolders + 
						[SUBFOLDER_ROOTKIT,
							SUBFOLDER_RAT,
							SUBFOLDER_SPYWARE]		
	WindowsSubFolders = LinuxSubFolders +
						[SUBFOLDER_CRYPTER,
							SUBFOLDER_EXPLOITKIT]
	AndroidSubFolders = LinuxSubFolders +
						[SUBFOLDER_EXPLOITKIT]	
	WebSubFolders = [SUBFOLDER_WEBSHELL,
						SUBFOLDER_EXPLOITKIT]

	FileStructure = {
		SUBFOLDER_WINDOWS 	:	WindowsSubFolders,
		SUBFOLDER_MSDOS 	:	MsDosSubFolders,
		SUBFOLDER_LINUX 	:	LinuxSubFolders,
		SUBFOLDER_UNIX 		:	LinuxSubFolders,
		SUBFOLDER_OSX 		:	LinuxSubFolders,
		SUBFOLDER_ANDROID 	:	AndroidSubFolders,
		SUBFOLDER_WEB		: 	WebSubFolders,
		SUBFOLDER_ANY		: 	WindowsSubFolders,		
		SUBFOLDER_OTHERS 	:	[],
	}

	def __init__(self, _base, _logger=sys.stdout):
		if _logger == None self.logger = Logger(sys.stdout)
		self.set_base(_base)
		FileStructure[self.get_base()] = OperatingSystems
		
	def __repr__(self):
		return "<Filesystem @{:s}>".format(self.get_base())
		
	def get_name(self):
		return self.name
		
	def set_base(self, _base):
		if not os.path.isdir(_base):
			raise Exception(VAULT_ERROR_INVALID_BASE_DIR.format(_base))
		self.print_success("Relocated file system to '{:s}'.".format(_base))
		self.base = _base
		
	def get_base(self):
		return self.base
	
	def create_filesystem(self):
		if (self.get_base() and os.path.isdir(self.get_base())):
			systems = self.FileStructure[self.get_base()]
			for system in systems:
				directory = os.path.join(self.get_base(), system)
				if not os.path.exists(directory):
					os.makedirs(directory)
					self.logger.print_success("Created '{:s}'".format(directory))
					subdirectories = self.FileStructure[system]
					for subdir in subdirectories:
						os.makedirs(subdir)
						self.logger.print_success("Created '{:s}'".format(subdir))
		else:
			raise Exception(VAULT_ERROR_INVALID_BASE_DIR.format(self.base))
				