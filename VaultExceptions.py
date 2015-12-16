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
# <date>2015-10-25</date>
# <url>https://github.com/infectedpacket</url>
#//////////////////////////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////////////////////////
# Imports Statements
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Globals and Constants
#
# Errors messages
#
ERR_FILE_NOT_FOUND		= 	"Specified file or directory '{:s}' does not exists."
ERR_EMPTY_OR_NULL_ARG	=	"Argument(s) provided cannot be null or empty."
ERR_NO_VAULT_FOUND		=	"No vault detected at '{:s}'."
ERR_VAULT_CREATION		=	"Error creating vault: {:s}."
ERR_FAILED_CONNECT_NET	=	"Failed to connect to the Internet: {:s}."
ERR_INVALID_URL			=	"Invalid URL: {:s}."
ERR_FAILED_DOWNLOAD		=	u"Failed to download file '{:s}'."
ERR_FAILED_METADATA		=	u"Failed to retrieve scan information for file '{:s}'."
ERR_NO_ARCHIVE			=	u"No archive defined or archive file does no exists."
ERR_FAILED_CONNECT_NET	=	"Failed to connect to the Internet: {:s}."
ERR_FILE_ALREADY_EXISTS	=	"File '{:s}' is already archived in the vault."
ERR_DB_FILE_EXIST		=	"Vault database already exists."
ERR_FILE_EXIST			=	"File already exists: {:s}."
ERR_DB_NO_DB_FILE		=	"No file specified for database."
ERR_CREATE_ARCHIVE		=	"Error while creating the archive: {:s}."
ERR_VIRUS_NO_FILE		=	"Virus object contains no file."
ERR_NO_URL_POST			=	u"Could not find URL in post: \n{:s}"
ERR_NO_URL_FOUND		=	u"No URL found in provided file(s)."
ERR_RSS_EMPTY_ENTRY		=	u"RSS entry does not contains any data."
#
# Information messages
#
INFO_VAULT_CREATED		=	"Vault successfully created."
INFO_HUNTERS_STARTED	=	"Succesfully started hunters threads."
INFO_ANALYZE_STARTED	=	"Succesfully started analyzers threads."
INFO_CTRLC_INT			=	"Control-C interrupt detected. Terminating..."
INFO_CONNECTED_NET		=	"Connected to the Internet."
INFO_PROGRAM_TERMINATE	=	"Program is terminating..."
INFO_DB_LOADED 			= 	"Loaded database '{:s}' successfully."
INFO_DB_ARCHIVE_ADDED 	= 	"Archive '{:s}' successfully added with id '{:d}'."
INFO_DB_FILE_ADDED 		= 	"\tAdded file '{:s}' to database."
INFO_DB_IDENT_ADDED 	= 	"\t\tAdded identification by '{:s}' as '{:s}'."
INFO_ARCHIVE_CREATED 	= 	"Created archive '{:s}'."
INFO_HUNT_COMPLETE 		= 	"Hunt completed. Thread '{:s}' is terminated."
INFO_NBENTRIES_FOUND 	= 	u"New entries found: {:d}."
INFO_CONNECTED_INTERNET		=	"Successfully connected to the Internet."
INFO_HUNT_THREADS_START		=	"Starting the hunters..."
INFO_HUNT_MALCODE_STARTED	=	"Started Malc0de hunter."
INFO_HUNT_LOCAL_STARTED		=	"Started local url hunter. Watching for files in '{:s}'."
#
WARN_NO_NEW_ENTRIES		=	u"No new entries found on malcode."
#
#//////////////////////////////////////////////////////////

class VaultException(Exception):

	def __init__(self, _message, _errors=None):
		super(Exception, self).__init__(_message)
		self.errors = _errors
		
		
class NullOrEmptyArgumentException(VaultException):

	def __init__(self):
		super(NullOrEmptyArgumentException, self).__init__(ERR_EMPTY_OR_NULL_ARG)
		
class FileNotFoundException(VaultException):

	def __init__(self, _info=""):
		super(FileNotFoundException, self).__init__(ERR_FILE_NOT_FOUND.format(_info))
	
class FileExistsException(VaultException):

	def __init__(self, _info=""):
		super(FileExistsException, self).__init__(ERR_FILE_EXIST.format(_info))
	
class VaultNotFoundException(VaultException):

	def __init__(self, _info=""):
		super(VaultNotFoundException, self).__init__(ERR_NO_VAULT_FOUND.format(_info))
		
class VaultCreationException(VaultException):

	def __init__(self, _info=""):
		super(VaultCreationException, self).__init__(ERR_VAULT_CREATION.format(_info))
		
class ConnectionFailedException(VaultException):

	def __init__(self, _info=""):
		super(ConnectionFailedException, self).__init__(ERR_FAILED_CONNECT_NET.format(_info))	

class InvalidUrlException(VaultException):

	def __init__(self, _info=""):
		super(InvalidUrlException, self).__init__(ERR_INVALID_URL.format(_info))			
		
class FileDownloadException(VaultException):

	def __init__(self, _info=""):
		super(FileDownloadException, self).__init__(ERR_FAILED_DOWNLOAD.format(_info))		

class MetadataRetrievalException(VaultException):

	def __init__(self, _info=""):
		super(MetadataRetrievalException, self).__init__(ERR_FAILED_METADATA.format(_info))	

class NoArchiveException(VaultException):

	def __init__(self, _info=""):
		super(NoArchiveException, self).__init__(ERR_NO_ARCHIVE.format(_info))
	
class NoUrlFoundException(VaultException):

	def __init__(self, _info=""):
		super(NoUrlFoundException, self).__init__(ERR_NO_URL_FOUND.format(_info))
	
class ArchiveExistsException(VaultException):

	def __init__(self, _info=""):
		super(ArchiveExistsException, self).__init__(ERR_FILE_ALREADY_EXISTS.format(_info))
				
class DatabaseFileExistsException(VaultException):

	def __init__(self, _info=""):
		super(DatabaseFileExistsException, self).__init__(ERR_DB_FILE_EXIST)
		
class NoDatabaseFileSpecifiedException(VaultException):

	def __init__(self, _info=""):
		super(NoDatabaseFileSpecifiedException, self).__init__(ERR_DB_NO_DB_FILE)
		
class ArchiveCreationException(VaultException):

	def __init__(self, _info="Unknown cause"):
		super(ArchiveCreationException, self).__init__(ERR_CREATE_ARCHIVE.format(_info))
		
class RssEntryNoContent(VaultException):

	def __init__(self, _info=""):
		super(RssEntryNoContent, self).__init__(ERR_RSS_EMPTY_ENTRY)
		