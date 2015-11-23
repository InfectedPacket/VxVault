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
PROGRAM_USAGE = "%(prog)s [-i] [-h|--help] (OPTIONS)"

__version_info__ = ('0','1','0')
__version__ = '.'.join(__version_info__)

#//////////////////////////////////////////////////////////////////////////////
# Imports Statements
import os
import sys
import time
import argparse

from Engine import Engine
from Logger import Logger
#//////////////////////////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////////////////////////
# Global variables and constants
YES	=	"Y"
NO	=	"n"

ERR_NO_VAULT_FOUND		=	"No vault detected at '{:s}'."
ERR_VAULT_CREATION		=	"Error creating vault: {:s}."
ERR_FAILED_CONNECT		=	"Failed to connect to the Internet."
ERR_FAILED_HUNTERS_START=	"Failed to start the hunters: {:s}."
ERR_FAILED_ANALYZE_START=	"Failed to start the analyzers: {:s}."

INFO_VAULT_CREATED		=	"Vault successfully created."
INFO_HUNTERS_STARTED	=	"Succesfully started hunters threads."
INFO_ANALYZE_STARTED	=	"Succesfully started analyzers threads."
INFO_CTRLC_INT			=	"Control-C interrupt detected. Terminating..."
INFO_CONNECTED_NET		=	"Connected to the Internet."

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
	help="Specifies the location of the vault to use.")
vault_options.add_argument("-vt", "--vtapi", 
	dest="vtapikey", 
	required=True,
	help="Provides the public key to use the API of VirusTotal.")	
vault_options.add_argument("--verbose", 
	dest="verbose", 
	action="store_true",
	help="Provides the public key to use the API of VirusTotal.")	
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

def main(args):
	#**************************************************************************
	# Initialization of the vault mechanisms
	# and objects.
	#**************************************************************************
	vt_api = args.vtapikey
	vault_base = args.base
	main_logger = Logger(
		_output	=	sys.stdout,
		_debug	=	args.verbose)
	engine = Engine(
		_base	=	vault_base,
		_vtapi	=	vt_api, 
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

	#**************************************************************************
	# Check if we have a connection to the Internet
	# if not, leave.
	#**************************************************************************
	if (not engine.can_connect_internet()):
		main_logger.print_error(ERR_FAILED_CONNECT)
		sys.exit(1)
	main_logger.print_success(INFO_CONNECTED_NET)
	#**************************************************************************
	# Start gathering malware from the Internet
	# by starting the various hunters.
	#**************************************************************************
	try:
		engine.start_hunters()
		main_logger.print_success(INFO_HUNTERS_STARTED)
	except Exception as e:
		main_logger.print_error(ERR_FAILED_HUNTERS_START.format(e.message))
		engine.shutdown()
		sys.exit(1)
	#**************************************************************************
	# Start the analyzer objects to classify
	# and sort malware into the vault.
	#**************************************************************************
	try:
		engine.start_analyzers()
		main_logger.print_success(INFO_ANALYZE_STARTED)
	except Exception as e:
		main_logger.print_error(ERR_FAILED_ANALYZE_START.format(e.message))
		engine.shutdown()
		sys.exit(1)	
	#**************************************************************************
	# Let the engine run until the user presses
	# Control-C to stop.
	#**************************************************************************
	try:
		time.sleep(1)
	except KeyboardInterrupt:
		main_logger.print_info(INFO_CTRLC_INT)
		engine.shutdown()
						
if __name__ == "__main__":
	banner()
	main(parser.parse_args())