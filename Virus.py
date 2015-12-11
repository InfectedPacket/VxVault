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
#
#//////////////////////////////////////////////////////////////////////////////
# Imports Statements
#
import os
import sys
import hashlib
import traceback
#
from parse import *
from Logger import Logger
from operator import itemgetter
from VaultExceptions import *
#
#//////////////////////////////////////////////////////////////////////////////
#
#//////////////////////////////////////////////////////////////////////////////
# Global variables and constants
INFO_GENERATE_ARCHIVE = "Generating archive name..."
INFO_BEST_GUESS = "Best value for '{:s}' found with score '{:d}': {:s}"
INFO_DETECTED_BY = "Detected by {:s} as '{:s}'."

ERR_NULL_EMPTY_PATH = "Path cannot be null or empty."
ERR_NO_DETECTION = "No detection information available, or file is not identified as malicious."
ERR_UNKNOWN_PROPERTY = "Unknown property"
#//////////////////////////////////////////////////////////////////////////////

class Virus(object):

	UNKNOWN			= 	"Unknown"
	NOT_DETECTED	=	"None"
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
	AV_VIPRE		=	"VIPRE"
	AV_VBA32		=	"VBA32"

	#
	FILE_EXE	=	"exe"
	FILE_DLL	=	"dll"
	FILE_SCR 	=	"scr"
	FILE_DOC	=	"doc"
	FILE_PDF	=	"pdf"
	FILE_APK	=	"apk"
	FILE_JAR	=	"jar"
	FILE_DOCX	=	"docx"
	FILE_ZIP	=	"zip"

	
	DEFAULT_IDENT_FORMAT	=	AV_KASPERSKY	
	
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

	VX_OS_DOS			= "MSDOS"
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
	DEFAULT_VX_CLASS 	= UNKNOWN
	DEFAULT_VX_SIZE		= 0
	DEFAULT_VX_VERS 	= UNKNOWN
	DEFAULT_VX_COUNTRY	= UNKNOWN
	DEFAULT_VX_OS		= UNKNOWN

	#**************************************************************************
	# List of properties about the malware to store
	#**************************************************************************
	VX_PROPERTY_NAME	= "name"
	VX_PROPERTY_SIZE	= "size"
	VX_PROPERTY_CLASS	= "vxclass"
	VX_PROPERTY_PASS	= "password"
	VX_PROPERTY_VERS	= "variant"
	VX_PROPERTY_OS		= "os"
	VX_PROPERTY_ARCHIVE	= "archive"
	VX_PROPERTY_DETECT	= "detect"
	VX_PROPERTY_MD5		= "md5"
	VX_PROPERTY_SHA1	= "sha1"
	VX_PROPERTY_SHA256	= "sha256"
	VX_PROPERTY_SSDEEP	= "ssdeep"

	VX_ARCHIVE_NAME_FORMAT = "{vxclass:s}.{vxos:s}.{vxname:s}.{vxvariant:s}"
	
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
	
	#**************************************************************************
	# List of operating systems, for use with classification and
	# storage of files on the file system.
	#**************************************************************************
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
	
	#**************************************************************************
	# Dictionary of malware identification format from
	# various security/AV vendors.
	#**************************************************************************
	AvNameFormats = {
		AV_ADAWARE		:	"{vxclass}.{name}.{variant}",
		AV_AVAST		:	"{os}:{name}",
		AV_AVG			:	"{name}.{variant}",
		AV_AVIRA		:	"{}/{name}.{variant}.{}",
		AV_BITDEFENDER	:	"{vxclass}.{name}.{variant}",
		AV_CLAM			:	"{os}.{vxclass}.{name}",
		AV_FORTINET		:	"{vxclass}/{name}",
		AV_COMODO		:	"{vxclass}.{os}.{name}.{variant}",
		AV_FSECURE		:	"{}:{}.{name}.{variant}",
		AV_GDATA		:	"{}:{}.{name}.{variant}",
		AV_MALBYTES		:	"MalwareBytes",
		AV_MCAFEE		:	"{name}!{variant}",
		AV_PANDA		:	"Panda",
		AV_SOPHOS		:	"{vxclass}:{name}",
		AV_ESET			:	"ESET-NOD32",
		AV_SYMANTEC		:	"{vxclass}.{name}.{variant}",
		AV_TENCENT		:	"{os}.{vxclass}.{name}.{variant}",
		AV_TRENDMICRO	:	"{vxclass}.{name}",
		AV_MICROSOFT	:	"Microsoft",
		AV_KASPERSKY	:	"{vxclass}.{os}.{name}.{variant}",
		AV_BAIDU		:	"{vxclass}.{os}.{name}.{variant}",
		AV_VIPRE		:	"{vxclass}.{os}.{name}!{variant}",
		AV_VBA32		:	"{vxclass}.{os}.{name}"
	}
	
	PayloadExtensions = [
		FILE_EXE, 
		FILE_DLL, 
		FILE_SCR, 
		FILE_DOC, 
		FILE_PDF, 
		FILE_APK, 
		FILE_JAR, 
		FILE_DOCX, 
		FILE_ZIP
	]
	
	#**************************************************************************
	# Used to transalte vendor-specific terms into a more
	# generic term to help with classification.
	#**************************************************************************
	NormalizedLabels = {
		"dos"	:	VX_OS_DOS,
		"msdos"	:	VX_OS_DOS,
		"w16"	:	VX_OS_WIN16,
		"win16"	:	VX_OS_WIN16,	
		"w32"	:	VX_OS_WIN32,
		"win32"	:	VX_OS_WIN32,
		"msil"	:	VX_OS_WIN32,
		"w64"	:	VX_OS_WIN32,
		"win64"	:	VX_OS_WIN32,
		"troj"	: 	VX_CLASS_TROJAN,
		"not_a_virus_adware": VX_CLASS_ADWARE,
		"suspected of trojan": 	VX_CLASS_TROJAN,
		"trojan_psw"	: 	VX_CLASS_TROJAN,
		"troj_gen"		: 	VX_CLASS_TROJAN,
		"trojan-spy"	: 	VX_CLASS_SPYWARE,
		"trojware"		: 	VX_CLASS_TROJAN,
		"heur:trojan"	:	VX_CLASS_TROJAN,
		"heur_trojan_downloader"	:	VX_CLASS_TROJAN,
		"heur_trojan"	:	VX_CLASS_TROJAN
	}
	
	def __init__(self, _logger=None):
		#**************************************************************************
		# Creates the logger object.
		#**************************************************************************
		if _logger == None: self.logger = Logger(sys.stdout)
		else: self.logger = _logger
		
		#**************************************************************************
		# Files of the malware.
		#**************************************************************************
		self.files = []
		
		#**************************************************************************
		# Initialize default properties of the malware.
		#**************************************************************************
		self.properties = {}
		self.properties[Virus.VX_PROPERTY_NAME] = Virus.DEFAULT_VX_NAME
		self.properties[Virus.VX_PROPERTY_SIZE] = Virus.DEFAULT_VX_SIZE
		self.properties[Virus.VX_PROPERTY_CLASS] = Virus.DEFAULT_VX_CLASS
		self.properties[Virus.VX_PROPERTY_VERS] = Virus.DEFAULT_VX_VERS
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
			vers=self.get_variant(),
			size=int(self.get_size()/1024),
			vxclass=self.get_class(),
			os=self.get_os())
		return str


	def add_file(self, _file):
		"""Adds a file to the malware.
		
		This function adds a file to the malware. Malware can be 
		composed of one or many files. Using the add_file function,
		you specify the absolute path of a file part of the malware.
		
		Args:
			_file: Absolute path to a file part of the malware.

		Returns:
			None.

		Raises:
			Exception if the file is null or empty. Will also raise
			an exception if the file does not exists.
		"""
		#**********************************************************************
		# Checks if the file is already included in the list.
		#**********************************************************************
		if (not (_file in self.files)):
			vx_file = VirusFile(_file)
			self.files.append(vx_file)
			
	def add_dir(self, _dir):
		"""Adds all files in the given directory and subdirectories to the
		Virus object.
		
		This function will add all files and subdirectories within the specified
		directory to the Virus object, considering them as being part of the same
		malware.
		
		Args:
			_dir: directory containing the files and subdirectories to add.
			
		Returns:
			None.
			
		Raises:
			Exception if the directory is null or empty. Will also raise
			an exception if the directory does not exists.
		"""
		if (_dir and len(_dir) > 0):
			if (os.path.exists(_dir)):
				for root, dirs, files in os.walk(_dir):
					for name in files:
						vx_file = VirusFile(os.path.join(root, name))
						self.files.append(vx_file)
			else:
				raise FileNotFoundException(_dir)
		else:
			raise NullOrEmptyArgumentException()
		
	def set_property(self, _property, _value):
		self.properties[_property] = _value

	def get_property(self, _property):
		return self.properties[_property]
		
	def get_archive(self):
		return self.get_property(Virus.VX_PROPERTY_ARCHIVE)

	def set_archive(self, _archive):
		self.set_property(Virus.VX_PROPERTY_ARCHIVE, _archive)

	def get_password(self):
		return self.get_property(Virus.VX_PROPERTY_PASS)

	def set_password(self, _password):
		self.set_property(Virus.VX_PROPERTY_PASS, _password)

	def get_file(self):
		if (len(self.files) > 0):
			return self.files[0]
		else:
			return []
		
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

	def set_variant(self, _version):
		self.set_property(Virus.VX_PROPERTY_VERS, _version)

	def get_variant(self):
		return self.get_property(Virus.VX_PROPERTY_VERS)

	def is_detected(self):
		return not self.is_undetected()
		
	def is_undetected(self):
		for file in self.files:
			if file.is_undetected():
				return True
		return False
		
	def generate_archive_name(self, _extension):
		chars = "\\`*:{}[]()>#+-!$&=\"\'"
		vx_name = self._create_archive_filename()
		# 
		# If there any special character in the filename,
		# replace them with an authorized character.
		#
		for c in chars:
			vx_name = vx_name.replace(c, "_")
			
		vx_archive = "{:s}.{:s}".format(vx_name, _extension)
		self.set_archive(vx_archive)
		return vx_archive
	
	def get_archive_sha1(self):
		""" Gets the SHA1 hash of the archive file associated with this malware.
		
		This function will return the SHA1 hash of the archive file associated with
		this malware. If no archive file has been created or exists, the function
		raises a NoArchiveException.
		
		Args:
			None.
			
		Returns:
			SHA1 hash hex digest in string.
			
		Raises:
			NoArchiveException: If not archive file exists for the current virus object.
		
		"""
		archive = self.get_archive()
		if (archive and len(archive) > 0 and os.path.isfile(archive)):
			vx_archive = VirusFile(archive)
			return vx_archive.get_sha1()
		else:
			raise NoArchiveException()
	
	def _create_archive_filename(self):
		self.logger.print_debug(INFO_GENERATE_ARCHIVE)
		vx_file = self.get_file()
		
		# Output format of the filename of the archived 
		# malware.
		filename_fmt = Virus.VX_ARCHIVE_NAME_FORMAT

		# If there's already an ident with the desired
		# filename format, just use the ident.
		if vx_file.is_detected_by(Virus.DEFAULT_IDENT_FORMAT):
			return vx_file.get_detection_by(Virus.DEFAULT_IDENT_FORMAT)
		
		# Make sure the properties needed are available
		# by generating them from the idents found.
		self.generate_properties()
		vx_class = self.get_class()
		vx_os = self.get_os()
		vx_name = self.get_name()
		vx_variant = self.get_variant()
		
		# Verify if we have a name/label specific to the file.
		vx_name = self.get_name()
		archive_name = ""
		
		# If not, include the MD5 as a unique identifier
		# of the malware.
		if (vx_name == Virus.UNKNOWN):
			vx_filename = vx_file.get_file()
			#
			# Remove the extension if it's included.
			# 
			if (u"." in vx_filename):
				vx_filename = vx_filename.split(u".")[0]
			vx_md5 = vx_file.get_md5()
			archive_name = "{:s}.{:s}".format(vx_filename, vx_md5.upper())
		else:
			archive_name = filename_fmt.format(vxclass=vx_class,
				vxos=vx_os, vxname=vx_name, vxvariant=vx_variant)
		
		return archive_name
	
	def generate_properties(self):
		vx_class = self.get_class()
		vx_os = self.get_os()
		vx_name = self.get_name()
		vx_variant = self.get_variant()

		#**********************************************************************
		# Attempts to figure the class of the malware based
		# on AV idents.
		#**********************************************************************
		if (vx_class == Virus.UNKNOWN):
			try:
				vx_class = self._guess_property_from_scans(Virus.VX_PROPERTY_CLASS)
			except:
				vx_class = Virus.UNKNOWN
			
			#
			# In some case, additional data is added in the
			# class of the malware, i.e. HEUR or  not-a-virus (for Adware)
			# This is removed to have uniform properties.
			if (u":" in vx_class):
				vx_class = vx_class.split(u":")[1]
			
			if (vx_class.lower() in Virus.NormalizedLabels):
				vx_class = Virus.NormalizedLabels[vx_class.lower()]
			self.set_class(vx_class)
			
		#**********************************************************************
		# Attempts to figure the target OS of the malware based
		# on AV idents.
		#**********************************************************************
		if (vx_os == Virus.UNKNOWN):
			try:
				vx_os = self._guess_property_from_scans(Virus.VX_PROPERTY_OS)				
			except:
				vx_os = Virus.UNKNOWN
				
			if (vx_os.lower() in Virus.NormalizedLabels):
				vx_os = Virus.NormalizedLabels[vx_os.lower()]
			self.set_os(vx_os)
			
		#**********************************************************************
		# Attempts to figure the name of the malware based
		# on AV idents.
		#**********************************************************************
		if (vx_name == Virus.UNKNOWN):
			try:
				vx_name = self._guess_property_from_scans(Virus.VX_PROPERTY_NAME)				
			except:
				vx_name = Virus.UNKNOWN

			self.set_name(vx_name)
			
		#**********************************************************************
		# Attempts to figure the variant/strain of the malware based
		# on AV idents.
		#**********************************************************************
		if (vx_variant == Virus.UNKNOWN):
			try:
				vx_variant = self._guess_property_from_scans(Virus.VX_PROPERTY_VERS)
			except:
				vx_variant = Virus.UNKNOWN
				
			self.set_variant(vx_variant)

	
	def _guess_property_from_scans(self, _property):
		self.logger.print_debug("Generating value for property '{:s}'.".format(_property))
		vx_file = self.get_file()
		#**********************************************************************
		# Verifies if the given property is available in the idents,
		# i.e. the property is CLASS, OS, NAME, or VARIANT.
		#**********************************************************************
		if (_property in Virus.VirusIdentItems):
			#******************************************************************
			# Checks if the default ident, i.e. an ident which usually contains
			# all the information we need, is present in the list of idents.
			# If so, use it to generate the value to the given property.
			#******************************************************************
			if (vx_file.is_detected_by(Virus.DEFAULT_IDENT_FORMAT)):
				ident = vx_file.get_detection_by(Virus.DEFAULT_IDENT_FORMAT)
				self.logger.print_debug(INFO_DETECTED_BY.format(Virus.DEFAULT_IDENT_FORMAT, ident))
				name_fmt = Virus.AvNameFormats[Virus.DEFAULT_IDENT_FORMAT]
				id_items = parse(name_fmt, ident)
				return id_items[_property]
			else:
			#
			# Otherwise, iterate thru all the available idents and parse them.
			# Retrieve the required property if available. Each time we 
			# successfully retrieve the property, stored it in a dictionary
			# along the number of times it was seen.
			# At the end, consider the value most often observed in the idents,
			# if there is a draw, select the first one.
			#
				try:
					scoreboard = {}
					for (av, name_fmt) in Virus.AvNameFormats.iteritems():
						if (vx_file.is_detected_by(av)):
							ident = vx_file.get_detection_by(av)
							id_items = parse(name_fmt, ident)

							if (id_items and _property in id_items.named and _property != None):
								property_value = id_items[_property]
								if (property_value in scoreboard):
									scoreboard[property_value] += 1
								else:
									scoreboard[property_value] = 1
								
					if (len(scoreboard) > 0):
						max_value = max(scoreboard.values())
						best_value = [prop for prop,val in scoreboard.items() if val == max_value]
						self.logger.print_debug(INFO_BEST_GUESS.format(_property, max_value, best_value[0]))
						return best_value[0]
					else:
						raise Exception(ERR_NO_DETECTION)
				except Exception as e:
					print(e.message)
					return Virus.UNKNOWN
		else:
			raise Exception(ERR_UNKNOWN_PROPERTY)
	
	
class VirusFile(object):

	def __init__(self, _file):
		#******************************************************************
		# Verifies if the providesd argument is not null/empty.
		#******************************************************************
		if (_file and len(_file) > 0):
			#**************************************************************
			# Verifies if the file exists.
			#**************************************************************
			if os.path.isfile(_file):
				#**************************************************************************
				# Initialize the dictionary of identifications by different
				# AV products.
				#**************************************************************************
				self.idents = {}
				
				self.file = _file
				self.hashes =  {}
				self._get_hashes()
			else:	
				raise FileNotFoundException(_file)
		else:
			raise NullOrEmptyArgumentException()

	def __str__(self):
		return self.file

	def add_ident(self, _av, _ident):
		"""Adds a anti-virus vendor identification of the malware.
		
		This function adds an anti-virus vendot identification 
		of the malware into a dictionary structure, the name of 
		the vendor is used as the key and the value if the label/name
		given to the malware. 
		
		Args:
			_av: name of the anti-virus vendor
			_ident: name of the malware.

		Returns:
			None.

		Raises:
			Exception if the name of the vendor or identification is null or 
			empty. 
		"""
		if (_ident and len(_ident) > 0):
			ident = _ident.lower().strip()
			#**********************************************************************
			# Verifies if the arguments are not null/empty.
			#**********************************************************************
			if (len(_av) > 0 and
				len(ident) > 0 and 
				ident != Virus.NOT_DETECTED):
				self.idents[_av] = _ident
			else:
				raise Exception(ERR_EMPTY_NULL_ARGS)
		else:
			raise Exception(ERR_EMPTY_NULL_ARGS)			
			
	def set_antiviral_results(self, _detections = {}):
		self.idents = _detections
		
	def get_antiviral_results(self):
		return self.idents
	
	def is_undetected(self):
		return len(self.idents) == 0
	
	def is_detected_by(self, _av):
		if (self.idents and len(self.idents) > 0):
			return (_av in self.idents)
		return False
	
	def get_detection_by(self, _av):
		if (self.idents and len(self.idents) > 0):
			if (self.is_detected_by(_av)):
				return self.idents[_av]
		return None
			
	def _set_hash(self, _hash, _value):
		self.hashes[_hash] = _value
		
	def _get_hash(self, _hash):
		return self.hashes[_hash]
	
	def get_path(self):
		return os.path.dirname(self.file)
		
	def get_file(self):
		return os.path.basename(self.file)

	def get_extension(self):
		return os.path.splitext(self.file)[1]
		
	def get_absolute(self):
		return os.path.abspath(self.file)
	
	def _get_hashes(self):
		"""
		Generates the hashes for the file and saves the results.
		
		This function will generates the MD5, SHA1 and SHA256 hashes of the
		file. The results are saved into the properties of the object. The value
		stored is the hexdigest of the hash in string format.
		
		Args:
			None.
			
		Returns:
			None.
			
		Raises:
			None.
		"""
		file = self.get_absolute()
		hash_md5  	= 	hashlib.md5()
		hash_sha1 	= 	hashlib.sha1()
		hash_sha256 =	hashlib.sha256()
		
 		with open(file, "rb") as f:
  			for chunk in iter(lambda: f.read(4096), b""):
				#
				# Include more hashes here as needed.
				#
				hash_md5.update(chunk)
				hash_sha1.update(chunk)
				hash_sha256.update(chunk)
				
		md5 	=	hash_md5.hexdigest()
		sha1 	= 	hash_sha1.hexdigest()
		sha256 	= 	hash_sha256.hexdigest()
		
		self.set_md5(md5)
		self.set_sha1(sha1)
		self.set_sha256(sha256)
		
		
	def set_md5(self, _value):
		self._set_hash(Virus.VX_PROPERTY_MD5, _value)
		
	def get_md5(self):
		return self._get_hash(Virus.VX_PROPERTY_MD5)
		
	def set_sha1(self, _value):
		self._set_hash(Virus.VX_PROPERTY_SHA1, _value)
		
	def get_sha1(self):
		return self._get_hash(Virus.VX_PROPERTY_SHA1)
		
	def set_sha256(self, _value):
		self._set_hash(Virus.VX_PROPERTY_SHA256, _value)
		
	def get_sha256(self):
		return self._get_hash(Virus.VX_PROPERTY_SHA256)
	
	def set_ssdeep(self, _ssdeep):
		self._set_hash(Virus.VX_PROPERTY_SSDEEP, _ssdeep)
		
	def get_ssdeep(self):
		return self._get_hash(Virus.VX_PROPERTY_SSDEEP)

	def matches_md5(self, _md5):
		return self.get_md5() == _md5
		
	def matches_sha1(self, _sha1):
		return self.get_sha1() == _sha1
		
	def matches_sha256(self, _sha256):
		return self.get_sha256() == _sha256	

	def matches_ssdeep(self, _ssdeep):
		return self.get_ssdeep() == _ssdeep			