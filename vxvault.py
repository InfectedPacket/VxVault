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
#
# You are free to use and modify this code for your own software 
# as long as you retain information about the original author
# in your code as shown below.
#
# <author>Jonathan Racicot</author>
# <email>infectedpacket@gmail.com</email>
# <date>2015-03-26</date>
# <url>https://github.com/infectedpacket</url>
#//////////////////////////////////////////////////////////////////////////////
# Program Information
#
PROGRAM_NAME = "vxvault"
PROGRAM_DESC = ""
PROGRAM_USAGE = "%(prog)s -a PATH|-i PATH|--hunt -vt APIKEY [-p PASSWORD] [-v]| [-h|--help]"

__version_info__ = ('0','1','0')
__version__ = '.'.join(__version_info__)

#//////////////////////////////////////////////////////////////////////////////
# Imports Statements
import os
import sys
import time
import signal
import argparse
import traceback
#
from Engine import Engine
from Logger import Logger
#
from VaultExceptions import *
#
#//////////////////////////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////////////////////////
# Global variables and constants
YES	=	"Y"
NO	=	"n"

ASK_CREATE_VAULT		=	"Would you like to create one? [Y/n]"

#//////////////////////////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////////////////////////
# Argument Parser Declaration
#
usage = PROGRAM_USAGE
parser = argparse.ArgumentParser(
	usage=usage, 
	prog=PROGRAM_NAME, 
	version="%(prog)s "+__version__, 
	description=PROGRAM_DESC)
	
vault_options = parser.add_argument_group("Vault Options", 
	"Sets basic options for the vault.")
vault_options.add_argument("-b", "--base", 
	dest="base", 
	required=True,
	default=os.getcwd(),
	help="Specifies the base directory of the vault.")
vault_options.add_argument("-vt", "--vtapi", 
	dest="vtapikey", 
	required=True,
	help="Specifies the public key to use the API of VirusTotal.")	
vault_options.add_argument("-a", "--add", 
	dest="newfile",
	help="File or directory of a single malware to add to the vault.")
vault_options.add_argument("-i", "--import", 
	dest="import_dir",
	help="Specifies a directory containing multiple malware to import into the vault.")
vault_options.add_argument("-p", "--password", 
	dest="password",
	default="",
	help="Specifies the password to used for encrypting archives containing the malware.")
vault_options.add_argument("--hunt", 
	dest="hunt_mode",
	action="store_true",
	help="Starts the vault in hunt mode.")
vault_options.add_argument("--verbose", 
	dest="verbose", 
	action="store_true",
	help="Displays diagnostic messages while VxVault is running.")	
#//////////////////////////////////////////////////////////////////////////////

def banner():
    print("Copyright (C) 2015  Jonathan Racicot <jonathan.racicot@rmc.ca>")
    print(
    """
    This program comes with ABSOLUTELY NO WARRANTY. This is
    free software, and you are welcome to redistribute it
    under certain conditions. See the GNU General Public
    License v3 for more information. 
    """)

def KeyboardInterruptHandler(_signal, _frame):
	print("Ctrl-C detected")
	engine.shutdown()
	sys.exit(0)
	
def main(args):
	#**************************************************************************
	# Initialization of the vault mechanisms
	# and objects.
	#**************************************************************************
	vt_api = args.vtapikey.strip()
	vault_base = args.base.strip()
	debug = args.verbose
	password = args.password
	
	signal.signal(signal.SIGINT, KeyboardInterruptHandler)
	
	main_logger = Logger(
		_output	=	sys.stdout,
		_debug	=	debug)
		
	global engine
	engine	= Engine(
		_base	=	vault_base,
		_vtapi	=	vt_api, 
		_password = password,
		_logger	=	main_logger)
		
	#**************************************************************************
	# Verify if the vault already exists at the
	# given base.
	#**************************************************************************
	if not engine.vault_is_created():
		# If the vault is not created, confirm if the user want
		# to create it.
		main_logger.print_warning(ERR_NO_VAULT_FOUND.format(vault_base))
		user_answer = main_logger.get_input(ASK_CREATE_VAULT)
		do_create = (user_answer == YES)
		if (do_create):
			try:
				engine.create_vault()
				main_logger.print_success(INFO_VAULT_CREATED)
			except Exception as e:
				main_logger.print_error(ERR_VAULT_CREATION.format(e.message))
				sys.exit(1)
		else:
			sys.exit(1)

	#**************************************************************************
	# Check if we have a connection to the Internet
	# if not, leave.
	#**************************************************************************
	if (not engine.can_connect_internet()):
		main_logger.print_error(ERR_FAILED_CONNECT)
		sys.exit(1)
	main_logger.print_success(INFO_CONNECTED_NET)

	try:
	#**************************************************************************
	# Functions
	#**************************************************************************
	#
	# Add new item to vault:
	#
	#**************************************************************************
		if (args.newfile):
			newfile = args.newfile.strip()
			if (os.path.isfile(newfile)):
				engine.add_single_file_virus(newfile)
			elif (os.path.isdir(newfile)):
				engine.add_single_dir_virus(newfile)
			elif (newfile[0:4].lower() == "http"):
				engine.add_http_file_virus(newfile)
			else:
				raise FileNotFoundException(newfile)
	#**************************************************************************
	# Import all malware from the given directory:
	#**************************************************************************
		elif (args.import_dir):		
			source_dir = args.import_dir
			#
			# If the user specified a file rather than a directory,
			# add the file.
			#
			if (os.path.isfile(source_dir)):
				engine.add_single_file_virus(source_dir)	
			elif (os.path.isdir(source_dir)):
				engine.add_multiple_virii_from_dir(source_dir)
			else:
				raise FileNotFoundException(source_dir)
		elif (args.hunt_mode):
			engine.start_malware_hunt()
	#
	#**************************************************************************
	#
	except Exception as e:
		main_logger.print_error(e.message)
		traceback.print_exc()
		
	#**************************************************************************
	# Clean up
	#**************************************************************************
	main_logger.print_warning(INFO_PROGRAM_TERMINATE)
	engine.shutdown()
			
			
if __name__ == "__main__":
	banner()
	main(parser.parse_args())