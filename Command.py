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

class Property(object):

	def __init__(self, _name, _value="", _desc=""):
	
	def set_name(self, _name):
		if _name:
			self.name = _name
		else:
			raise Exception(ERR_NULL_OR_EMPTY.format("name"))
		
	def get_name(self):
		return self.name

	def set_value(self, _value):
		self.value = _value
		
	def get_value(self):
		return self.value
		
	def set_desc(self, _desc):
		self.desc = _desc
		
	def get_desc(self):
		return self.desc
		
class Command(object):

	def __init__(self, _cmd, _help="", _usage="", _choices=[]):
		self.subcmd = []
		self.properties = []
		self.set_cmd(_cmd)
		self.set_help(_help)
		self.set_usage(_usage)
		self.set_choices(_choices)
	
	def set_cmd(self, _cmd):
		if (_cmd):
			self.cmd = _cmd
		else:
			raise Exception(ERR_NULL_OR_EMPTY.format("cmd"))
		
	def get_cmd(self):
		return self.cmd

	def set_help(self, _help):
		self.help = _help
		
	def get_help(self):
		return help
		
	def set_choices(self, _choices):
		self.choices = _choices
		
	def get_choices(self):
		return choices
		
	def set_usage(self, _usage):
		self.usage = _usage
		
	def get_usage(self):
		return self.usage
		
	def add_subcommand(self, _command):
		if (isinstance(_command, Command)):
			self.subcmd.append(_command)
		else:
			raise Exception("Only 'Command' objects can be added as subcommands. Received '{:s}'.".format(type(_command)))

	def add_property(self, _property):
		if (isinstance(_property, Property)):
			self.properties.append(_property)
		else:
			raise Exception("Only 'Property' objects can be added as properties. Received '{:s}'.".format(type(_command)))

	def get_subcommands(self):
		return self.subcmd
		
	def get_properties(self):
		return self.properties
	
class CommandTree(object):

	CMD_SET			=	"set"
	CMD_SET_HELP	=	"Sets the value of a property."
	CMD_SET_USE		=	"set <property> <value>"
	
	CMD_SHOW		=	"show"
	CMD_SHOW_HELP	=	"Display the current value of the property."
	CMD_SHOW_USE	=	"show <property>"
	
	CMD_HELP 		= 	"help"
	CMD_QUIT 		= 	"quit"
	
	def __init__(self):
		self.root = Command(_cmd="root")
	
	def create_tree(self):
		cmd_set = Command(
			_cmd 	= CMD_SET, 
			_help 	= CMD_SET_HELP,
			_usage	= CMD_SET_USE)
		cmd_show = Command(
			_cmd 	= CMD_SHOW,
			_help 	= CMD_SHOW_HELP,
			_usage	= CMD_SHOW_USE
		)
		
		self.root.add_subcommand(cmd_set)
		self.root.add_subcommand(cmd_show)
	
	def search_command(self, _cmd, _node):
	
		if _node == None or _node = []:
			return None
		
		if (_cmd == _node.get_cmd()):
			return _node
		else:
			subcmds = _node.get_subcommands()
			if len(subcmds) <= 0: return None
			else:
				for subcmd in subcmds:
					found_cmd = self.search(_cmd, subcmd)
					if found_cmd != None:
						return found_cmd
						
class CommandSet(Command):

	def __init__(self):
		pass