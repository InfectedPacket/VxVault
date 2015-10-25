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
from Logger import Logger
#//////////////////////////////////////////////////////////


#//////////////////////////////////////////////////////////
# Parameter information
class ShellConfig:

	CMD_SET			=	"set"
	CMD_SHOW		=	"show"
	CMD_NEWFAULT	= 	"new-vault"	
	CMD_HELP = 'help'
	CMD_QUIT = 'quit'

	PROPERTY_VX_PASSWORD		= "vxpass"
	DEFAULT_VX_PASSWORD 		= "infect3d"		
	
	PROMPT = "<<< "
	
	properties = {
		PROPERTY_VX_PASSWORD	:	DEFAULT_VX_PASSWORD
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
					}
	}
	

		

class Shell(object):
	
	def __init__(self, _output=sys.stdout):
		"""
			Initializes the user interface by defining a Logger object
			and defining the standard output.
		"""
		self.output = _output
		self.logger = Logger(_output, _debug=True)

	def start(self):
		"""
			Starts the main loop of the interactive shell.
		"""
		
		# Command entered by the user
		cmd = ""
		self.logger.print_info("Type 'help' to show a list of available commands.")
		
		while (cmd.lower() != ShellConfig.CMD_QUIT):
			try:
				self.output.write(ShellConfig.PROMPT)
				user_input = sys.stdin.readline()
				tokens = user_input.rstrip().split()
				cmd = tokens[0]
				if (cmd.lower() == ShellConfig.CMD_QUIT):
					pass
				elif (cmd.lower() == ShellConfig.CMD_HELP):
					if (len(tokens) == 1):
						self.logger.print_info("{:s} <property> <value>".format(ShellConfig.CMD_SET))
						self.logger.print_info("{:s} <property>".format(ShellConfig.CMD_SHOW))
						self.logger.print_info("{:s}".format(ShellConfig.CMD_NEWFAULT))
						self.logger.print_info("{:s} <command>".format(ShellConfig.CMD_HELP))
						self.logger.print_info("{:s}".format(ShellConfig.CMD_QUIT))
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
						vxvault = Vault(param, self.logger)
						vxvault.file_system.create_filesystem()
					else:
						self.logger.print_info("{:s} <property> <value>".format(ShellConfig.CMD_SET))
						
				else:
					self.logger.print_error("Unknown command {:s}.".format(cmd))
			except Exception as e:
				self.logger.print_error("An exception as occured: {:s}".format(e.message))
				traceback.print_exc(file=sys.stdout)
