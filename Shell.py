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
#
# You are free to use and modify this code for your own software 
# as long as you retain information about the original author
# in your code as shown below.
#
# <author>Jonathan Racicot</author>
# <email>infectedpacket@gmail.com</email>
# <date>2015-03-26</date>
# <url>https://github.com/infectedpacket</url>
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Imports Statements
import sys
import traceback

from Vault import Vault
from Engine import Engine
from Logger import Logger

#TODO: Remove following imports / move to Engine
from DataSources import *
from Hunters import *
import urllib2
from BeautifulSoup import BeautifulSoup

#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Globals and Constants
ERR_NULL_OR_EMPTY	=	"Value for variable '{:s}' cannot be null or empty."
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Parameter information
class ShellConfig:

	CMD_SET			=	"set"
	CMD_SHOW		=	"show"
	CMD_NEWFAULT	= 	"new-vault"	
	CMD_NEWVX		=	"new-vx"
	CMD_HUNT		=	"hunt"
	CMD_TEST		=	"test"	
	CMD_HELP = 'help'
	CMD_QUIT = 'quit'

	PROPERTY_VX_PASSWORD		= "vxpass"
	PROPERTY_VX_SCANS			= "scans"
	DEFAULT_VX_PASSWORD 		= "infect3d"

	PROPERTY_VX_COMPRESS		= "archiver"
	WIN32_PROGRAM_7ZIP			= "c:\\program files(x86)\\7-zip\7z.exe"
	LINUX_PROGRAM_7ZIP			= "/usr/bin/7z"
	DEFAULT_VX_COMPRESS 		= LINUX_PROGRAM_7ZIP
	
	PROMPT = "<<< "
	
	properties = {
		PROPERTY_VX_PASSWORD	:	DEFAULT_VX_PASSWORD,
		PROPERTY_VX_COMPRESS	:	DEFAULT_VX_COMPRESS
	}	
	
	commands = {
			"debug" : {
					"cmd"       : "debug",
					"help"      : "Enables debug mode.",
					"choices"   : ["true", "false"],
					},
			CMD_SET : {
					"cmd"       : "set",
					"help"      : "Sets the value of a property.",
					"choices"	: properties.keys()
					},
			CMD_SHOW : {
					"cmd"       : "show",
					"help"      : "Shows the value of a property.",
					"choices"	: properties.keys()
					},		
			CMD_NEWFAULT : {
					"cmd"       : "new-vault",
					"help"      : "Creates a new vault.",
					"choices"	: []
					},
			CMD_NEWVX : {
					"cmd"       : "new-vx",
					"help"      : "Creates a new malware object from file. If a directory is provided, multiple 'Virus' objects are created from the files stored in the directory.",
					"choices"	: []
					}					
	}
	

		

class Shell(object):
	
	def __init__(self, _debug=False, _output=sys.stdout):
		"""
			Initializes the user interface by defining a Logger object
			and defining the standard output.
		"""
		self.output = _output
		self.logger = Logger(_output=_output, _debug=_debug)
		if (_debug):
			self.logger.print_debug("Debug mode: ON")
		
	def start(self, _base, _vtapi):
		"""
			Starts the main loop of the interactive shell.
		"""
		
		# Command entered by the user
		cmd = ""
		engine = Engine(_base, _vtapi, _logger=self.logger)
		self.logger.print_info("Type 'help' to show a list of available commands.")
		
		while (cmd.lower() != ShellConfig.CMD_QUIT):
			try:
				self.output.write(ShellConfig.PROMPT)
				user_input = sys.stdin.readline()
				tokens = user_input.rstrip().split()
				cmd = ""
				if len(tokens) > 0:
					cmd = tokens[0]
				if (cmd.lower() == ShellConfig.CMD_QUIT):
					engine.stop_hunters()
					engine.stop_analyzers()
				elif (cmd.lower() == ShellConfig.CMD_HELP):
					if (len(tokens) == 1):
						self.logger.print_info("{:s} <property> <value>".format(ShellConfig.CMD_SET))
						self.logger.print_info("{:s} <property>".format(ShellConfig.CMD_SHOW))
						self.logger.print_info("{:s} <file|directory>".format(ShellConfig.CMD_NEWVX))
						self.logger.print_info("{:s} <base-directory>".format(ShellConfig.CMD_NEWFAULT))
						self.logger.print_info("{:s} <command>".format(ShellConfig.CMD_HELP))
						self.logger.print_info("{:s}".format(ShellConfig.CMD_QUIT))
						self.logger.print_info("{:s} malcode|(local <directory>|stopall)".format(ShellConfig.CMD_HUNT))
					else:
						param = tokens[1]
						if ((param in ShellConfig.commands.keys())):
							help_msg = ShellConfig.commands[param]['help']
							self.logger.print_info(help_msg)
							if (len(ShellConfig.commands[param]['choices']) > 0):
								choices_msg = ', '.join([ choice for choice in ShellConfig.commands[param]['choices']])
								self.logger.print_info("Available values: {:s}".format(choices_msg))
						else:
							self.logger.print_error("Unknown parameter/option: {:s}.".format(param))
				elif (cmd.lower() == ShellConfig.CMD_SHOW):
					if len(tokens) >= 2:
						for property in tokens[1:]:
							if property in ShellConfig.commands[ShellConfig.CMD_SHOW]["choices"]:
								self.logger.print_info("{:s} -> {}".format(property, ShellConfig.properties[property]))
							else:
								self.logger.print_error("Unknown property: {:s}".format(property))
					else:
						self.logger.print_info("{:s} <property>".format(ShellConfig.CMD_SHOW))
				elif (cmd.lower() == ShellConfig.CMD_SET):
					if len(tokens) == 3:
						property = tokens[1]
						value = tokens[2]
						if property in ShellConfig.commands[ShellConfig.CMD_SET]["choices"]:
							ShellConfig.properties[property] = value
							self.logger.print_info("{:s} -> {}".format(property, ShellConfig.properties[property]))
						else:
							self.logger.print_error("Unknown property: {:s}".format(property))
					else:
						self.logger.print_info("{:s} <property> <value>".format(ShellConfig.CMD_SET))
				elif (cmd.lower() == ShellConfig.CMD_NEWFAULT):
					if len(tokens) >= 2:
						param = ' '.join(tokens[1:])
						engine.create_vault(param)
					else:
						self.logger.print_info("{:s} <base-directory>".format(ShellConfig.CMD_NEWFAULT))
				elif (cmd.lower() == "load-vault"):
					if len(tokens) >= 2:
						param = ' '.join(tokens[1:])
						engine.load_vault(param)
					else:
						self.logger.print_info("{:s} <base-directory>".format(ShellConfig.CMD_NEWFAULT))						
				elif (cmd.lower() == ShellConfig.CMD_NEWVX):
					if len(tokens) >= 2:
						param = ' '.join(tokens[1:])
						vx = engine.generate_vx(param)
						engine.retrieve_vx_metadata(vx)
						self.logger.print_info("malware information:")
						self.logger.print_success("\tsize (kb)\t:{:d}".format(vx.get_size()))
						self.logger.print_success("\tmd5\t\t:{:s}".format(vx.md5()[param]))
						avs_detect = vx.get_antiviral_results()
						if (len(avs_detect) > 0):
							for (av, result) in avs_detect.iteritems():
								if (result != None):
									self.logger.print_success("\t{:s}\t\t\t:{:s}".format(av, result))
						else:
							self.print_error("No information retrieved for '{:s}'.".format(param))
					else:
						self.logger.print_info("{:s} <file|directory>".format(ShellConfig.CMD_NEWVX))
				elif (cmd.lower() == ShellConfig.CMD_HUNT):
					if len(tokens) >= 2:
						if (tokens[1] == "malcode"):
							engine.gather_vx_from_malcode()
							engine.start_vt_analyzer()
						elif (tokens[1] == "local"):
							vx_local = tokens[2]
							engine.gather_vx_from_local_files(vx_local)
							engine.start_vt_analyzer()
						elif (tokens[1] == "stopall"):
							engine.stop_hunters()
							engine.stop_analyzers()
						else:
							self.logger.print_error("Unknown option for '{:s}': {:s}".format(tokens[1], ShellConfig.CMD_HUNT))
					else:
						self.logger.print_error("{:s} malcode|(local <directory>|stopall)".format(ShellConfig.CMD_HUNT))
			
				elif (cmd.lower() == ShellConfig.CMD_TEST):		
					engine.start_vt_analyzer()
				else:
					self.logger.print_error("Unknown command {:s}.".format(cmd))
			except Exception as e:
				self.logger.print_error("An exception as occured: {:}".format(e.message))
				traceback.print_exc(file=sys.stdout)
