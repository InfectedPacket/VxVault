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
import sys
import hashlib
import traceback

from Logger import Logger
#//////////////////////////////////////////////////////////

VIRUS_ERROR_7Z_NOTFOUND = "Could not find archiving program: {:s}."

class Virus(object):

	VX_CLASS_VIRUS 		= "Virus"
	VX_CLASS_WORM		= "Worm"
	VX_CLASS_TROJAN 	= "Trojan"
	VX_CLASS_ROOTKIT	= "Rootkit"
	VX_CLASS_EXPLOIT	= "ExploitKit"
	VX_CLASS_SPYWARE	= "Spyware"
	VX_CLASS_WEBSHELL	= "WebShell"
	VX_CLASS_CRYPTER	= "Crypter"
	VX_CLASS_BACKDOOR	= "Backdoor"
	VX_CLASS_KEYLOGGER	= "Keylogger"
	VX_CLASS_OTHER		= "Other"
	VX_CLASS_UNKNOWN	= "Unknown"

	UNKNOWN			= "Unknown"
	DEFAULT_VX_NAME 	= UNKNOWN
	DEFAULT_VX_SIZE		= 0
	DEFAULT_VX_VERS 	= "1.00"
	DEFAULT_VX_CLASS	= VX_CLASS_UNKNOWN
	DEFAULT_VX_DATE		= "1900"
	DEFAULT_VX_COUNTRY	= UNKNOWN
	DEFAULT_VX_OS		= UNKNOWN

	EXTENSION_7Z		= ".7z"

	VX_PROPERTY_NAME	= "name"
	VX_PROPERTY_SIZE	= "size"
	VX_PROPERTY_CLASS	= "class"
	VX_PROPERTY_VERS	= "version"
	VX_PROPERTY_DATE	= "date"
	VX_PROPERTY_COUNTRY	= "country"
	VX_PROPERTY_OS		= "os"
	VX_PROPERTY_ARCHIVE	= "archive"
	VX_PROPERTY_MD5		= "md5"
	VX_PROPERTY_SHA1	= "sha1"
	VX_PROPERTY_SHA256	= "sha256"
	VX_PROPERTY_SSDEEP	= "ssdeep"

	VirusClasses = [
		VX_CLASS_VIRUS,
		VX_CLASS_WORM,
		VX_CLASS_TROJAN,
		VX_CLASS_ROOTKIT,
		VX_CLASS_EXPLOIT,
		VX_CLASS_SPYWARE,
		VX_CLASS_WEBSHELL,
		VX_CLASS_CRYPTER,
		VX_CLASS_BACKDOOR,
		VX_CLASS_KEYLOGGER
	]
		
	
	def __init__(self):
		self.files = []
		self.properties = {}
		self.properties[Virus.VX_PROPERTY_NAME] = Virus.DEFAULT_VX_NAME
		self.properties[Virus.VX_PROPERTY_SIZE] = Virus.DEFAULT_VX_SIZE
		self.properties[Virus.VX_PROPERTY_CLASS] = Virus.DEFAULT_VX_CLASS
		self.properties[Virus.VX_PROPERTY_VERS] = Virus.DEFAULT_VX_VERS
		self.properties[Virus.VX_PROPERTY_DATE] = Virus.DEFAULT_VX_DATE
		self.properties[Virus.VX_PROPERTY_COUNTRY] = Virus.DEFAULT_VX_COUNTRY
		self.properties[Virus.VX_PROPERTY_OS] = Virus.DEFAULT_VX_OS
		self.properties[Virus.VX_PROPERTY_ARCHIVE] = ""
		self.properties[Virus.VX_PROPERTY_MD5] = {}
		self.properties[Virus.VX_PROPERTY_SHA1] = {}
		self.properties[Virus.VX_PROPERTY_SHA256] = {}
		self.properties[Virus.VX_PROPERTY_SSDEEP] = {}

	def __repr__(self):
		vx_id = self.get_name()
		md5_hash_str = ""
		for (vxfile, vxhash) in self.md5().iteritems():
			md5_hash_str += vxhash
		megahash = hashlib.md5(md5_hash_str).hexdigest()
		return "{:s}.{:s}".format(vx_id, megahash)			

	def __str__(self):
		str = "{vx:s}.{vers:s} ({size:d}Kb):{vxclass:s}\t{os:s}".format(
			vx  =self.get_name(),
			vers=self.get_version(),
			size=int(self.get_size()/1024),
			vxclass=self.get_class(),
			os=self.get_os())
		return str


	def add_file(self, _file):
		self.files.append(_file)

	def get_archive(self):
		return self.get_property(Virus.VX_PROPERTY_ARCHIVE)

	def set_archive(self, _archive):
		self.set_property(Virus.VX_PROPERTY_ARCHIVE, _archive)

	def set_property(self, _property, _value):
		self.properties[_property] = _value

	def get_property(self, _property):
		return self.properties[_property]

	def get_files(self):
		return self.files

	def set_name(self, _name):
		self.set_property(Virus.VX_PROPERTY_NAME, _name)

	def get_name(self):
		return self.get_property(Virus.VX_PROPERTY_NAME)

	def set_class(self, _class):
		self.set_property(Virus.VX_PROPERTY_CLASS, _class)

	def get_class(self):
		return self.get_property(Virus.VX_PROPERTY_CLASS)

	def set_os(self, _os):
		self.set_property(Virus.VX_PROPERTY_OS, _os)

	def get_os(self):
		return self.get_property(Virus.VX_PROPERTY_OS)

	def set_version(self, _version):
		self.set_property(Virus.VX_PROPERTY_VERS, _version)

	def get_version(self):
		return self.get_property(Virus.VX_PROPERTY_VERS)

	def reset_size(self):
		self.set_property(Virus.VX_PROPERTY_SIZE, 0)

	def add_size(self, _size):
		current_size = self.get_size()
		new_size = current_size + _size
		self.set_property(Virus.VX_PROPERTY_SIZE, new_size)

	def get_size(self):
		return self.properties[Virus.VX_PROPERTY_SIZE]

	def get_country(self):
		return self.properties[Virus.VX_PROPERTY_COUNTRY]

	def get_date(self):
		return self.properties[Virus.VX_PROPERTY_DATE]

	def archive(self, _destination, _password, _7z):
		if (self.files and len(self.files) > 0):
			if not os.path.isfile(_7z):
				raise Exception(VIRUS_ERROR_7Z_NOTFOUND.format(_7z))

			vx_file = self.__repr__()	
			vx_dst_file = os.path.join(_destination, os.path.basename(vx_file))
			vx_dst_file += EXTENSION_7Z

			result = subprocess.call(
				[_7z, "a",
				 "-p{:s}".format(_password), "-y",
				 vx_dst_file] +
				self.files)
			self.set_archive(vx_dst_file)		
			return vx_dst_file
		else:
			raise Exception("No file specified.")


	def md5(self):
		files = self.get_files()
		md5 = self.properties[Virus.VX_PROPERTY_MD5]
		for file in files:
			hash = hashlib.md5()
 			with open(file, "rb") as f:
  				for chunk in iter(lambda: f.read(4096), b""):
					hash.update(chunk)
			md5[file] = hash.hexdigest()
		return md5

	def sha1(self):
		files = self.get_files()
		sha1 = self.properties[Virus.VX_PROPERTY_SHA1]
		for file in files:
			sha1[file] = ""
		return sha1

	def sha256(self):
		files = self.get_files()
		sha256 = self.properties[Virus.VX_PROPERTY_SHA256]
		for file in files:
			sha256[file] = ""
		return sha256

	def ssdeep(self):
		ssdeep = self.properties[Virus.VX_PROPERTY_SSDEEP]
		return ssdeep