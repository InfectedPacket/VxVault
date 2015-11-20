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

from parse import *
from Logger import Logger
from operator import itemgetter
#//////////////////////////////////////////////////////////

VIRUS_ERROR_7Z_NOTFOUND = "Could not find archiving program: {:s}."

class Virus(object):

	UNKNOWN			= "Unknown"

	AV_ADAWARE		=	"Ad-Aware"
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
	AV_TENCENT		=	"Tencent"
	AV_TRENDMICRO	=	"Trend Micro"
	AV_MICROSOFT	=	"Microsoft"
	AV_KASPERSKY	=	"Kaspersky"
	AV_BAIDU		=	"Baidu-International"

	VX_CLASS_VIRUS 		= "Virus"
	VX_CLASS_ADWARE		= "Adware"
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
	VX_CLASS_UNKNOWN	= UNKNOWN

	VX_OS_DOS			= "DOS"
	VX_OS_WIN16			= "Win16"
	VX_OS_WIN32			= "Win32"
	VX_OS_WIN64			= "Win64"
	VX_OS_LINUX_32		= "Linux32"
	VX_OS_LINUX_64		= "Linux64"
	VX_OS_ANDROID		= "Android"
	VX_OS_MACOS			= "MacOS"
	VX_OS_WEB			= "Web"
	VX_OS_ANY			= "Any"
	
	DEFAULT_VX_NAME 	= UNKNOWN
	DEFAULT_VX_SIZE		= 0
	DEFAULT_VX_VERS 	= "A"
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
	VX_PROPERTY_DETECT	= "detect"
	VX_PROPERTY_MD5		= "md5"
	VX_PROPERTY_SHA1	= "sha1"
	VX_PROPERTY_SHA256	= "sha256"
	VX_PROPERTY_SSDEEP	= "ssdeep"

	VirusClasses = [
		VX_CLASS_VIRUS,
		VX_CLASS_ADWARE,
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
	
	OperatingSystems = [
		VX_OS_DOS,
		VX_OS_WIN16,
		VX_OS_WIN32,
		VX_OS_WIN64,
		VX_OS_LINUX_32,
		VX_OS_LINUX_64,
		VX_OS_ANDROID,
		VX_OS_MACOS,
		VX_OS_WEB,
		VX_OS_ANY
	]
	
	VirusIdentItems = [
		VX_PROPERTY_NAME,
		VX_PROPERTY_OS,
		VX_PROPERTY_CLASS,
		VX_PROPERTY_VERS
	]
	
	AvNameFormats = {
		AV_ADAWARE		:	"{}:{}.{name}.{variant}",
		AV_AVAST		:	"{os}:{name}",
		AV_AVG			:	"{name}.{variant}",
		AV_AVIRA		:	"{}/{name}.{variant}.{}",
		AV_BITDEFENDER	:	"{}:{}.{name}.{variant}",
		AV_CLAM			:	"{os}.{class}.{name}",
		AV_FORTINET		:	"{class}/{name}",
		AV_COMODO		:	"{class}.{os}.{name}.{variant}",
		AV_FSECURE		:	"{}:{}.{name}.{variant}",
		AV_GDATA		:	"{}:{}.{name}.{variant}",
		AV_MALBYTES		:	"MalwareBytes",
		AV_MCAFEE		:	"{name}!{variant}",
		AV_PANDA		:	"Panda",
		AV_SOPHOS		:	"{class}:{name}",
		AV_ESET			:	"ESET-NOD32",
		AV_SYMANTEC		:	"{class}.{name}.{variant}",
		AV_TENCENT		:	"{os}.{class}.{name}.{variant}",
		AV_TRENDMICRO	:	"{class}.{name}",
		AV_MICROSOFT	:	"Microsoft",
		AV_KASPERSKY	:	"{class}.{os}.{name}.{variant}",
		AV_BAIDU		:	"{class}.{os}.{name}.{variant}"
	}
		
	NormalizedLabels = {
		"dos"	:	VX_OS_DOS,
		"msdos"	:	VX_OS_DOS,
		"w16"	:	VX_OS_WIN16,
		"win16"	:	VX_OS_WIN16,	
		"w32"	:	VX_OS_WIN32,
		"win32"	:	VX_OS_WIN32,
		"w64"	:	VX_OS_WIN32,
		"win64"	:	VX_OS_WIN32,
		"troj"	: 	VX_CLASS_TROJAN,
		"troj_gen"		: 	VX_CLASS_TROJAN,
		"trojan-spy"	: 	VX_CLASS_SPYWARE,
		"trojware"		: 	VX_CLASS_TROJAN
	}
	
	def __init__(self, _logger=None):
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger		
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
		self.idents = {}

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

	def add_ident(self, _av, _ident):
		if (len(_av) > 0 and len(_ident) > 0 and _ident.lower().trim() != "none"):
			self.idents[_av] = _ident
		
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

	def set_antiviral_results(self, _detections = {}):
		self.idents = _detections
		
	def get_antiviral_results(self):
		return self.idents
	
	def is_detected_by(self, _av):
		if (self.idents and len(self.idents) > 0):
			return (_av in self.idents)
		return False
	
	def get_detection_by(self, _av):
		if (self.idents and len(self.idents) > 0):
			if (self.is_detected_by(_av)):
				return self.idents[_av]
		return None
	
	def _create_archive_filename(self):
		self.logger.print_debug("Generating archive name...")
		filename_fmt = "{vxclass:s}.{vxos:s}.{vxname:s}.{vxvariant:s}"
		vx_class = self.get_class()
		vx_os = self.get_os()
		vx_name = self.get_name()
		vx_variant = self.get_version()
		
		if (vx_class == Virus.UNKNOWN):
			vx_class = self._guess_property_from_scans(Virus.VX_PROPERTY_CLASS)
			if (vx_class in Virus.NormalizedLabels):
				vx_class = Virus.NormalizedLabels[vx_class.lower()]
			self.set_class(vx_class)
			
		if (vx_os == Virus.UNKNOWN):
			vx_os = self._guess_property_from_scans(Virus.VX_PROPERTY_OS)
			if (vx_os in Virus.NormalizedLabels):
				vx_os = Virus.NormalizedLabels[vx_os.lower()]
			self.set_os(vx_os)
			
		if (vx_name == Virus.UNKNOWN):
			vx_name = self._guess_property_from_scans(Virus.VX_PROPERTY_NAME)
			self.set_name(vx_name)
			
		if (vx_variant == Virus.UNKNOWN):
			vx_variant = self._guess_property_from_scans(Virus.VX_PROPERTY_VERS)
			self.set_version(vx_variant)
			
		archive_name = filename_fmt.format(vxclass=vx_class,
			vxos=vx_os, vxname=vx_name, vxvariant=vx_variant)
		return archive_name
	
	def _guess_property_from_scans(self, _property):
		self.logger.print_debug("Generating value for property '{:s}'.".format(_property))
		if (_property in Virus.VirusIdentItems):
			if (len(self.idents) > 0):
				if (self.is_detected_by(Virus.AV_KASPERSKY)):
					name_fmt = Virus.AvNameFormats[Virus.AV_KASPERSKY]
					id_items = parse(name_fmt, self.get_detection_by(Virus.AV_KASPERSKY))
					self.logger.print_debug("Value for '{:s}' found in Kaspersky ident: {:s}".format(_property, id_items[_property]))
					return id_items[_property]
				elif (self.is_detected_by(Virus.AV_TENCENT)):
					name_fmt = Virus.AvNameFormats[Virus.AV_TENCENT]
					id_items = parse(name_fmt, self.get_detection_by(Virus.AV_TENCENT))
					self.logger.print_debug("Value for '{:s}' found in Tencent ident: {:s}".format(_property, id_items[_property]))
					return id_items[_property]
				else:
					scoreboard = {}
					for (av, name_fmt) in Virus.AvNameFormats.items():
						id_items = parse(name_fmt, self.get_detection_by(av))
						if (_property in id_items):
							property_value = id_items[_property]
							if (property_value in scoreboard):
								scoreboard[property_value] += 1
							else:
								scoreboard[property_value] = 1
					max_value = max(scoreboard.values())
					best_value = [prop for prop,val in scoreboard.items() if val == max_value]
					self.logger.print_debug("Best value for '{:s}' found with score '{:d}': {:s}".format(_property, max_value, best_value[0]))
					return best_value[0]
			else:
				raise Exception("No malware infomation available.")
		else:
			raise Exception("Unknown property")
	
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