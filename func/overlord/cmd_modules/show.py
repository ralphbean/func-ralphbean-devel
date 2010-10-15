"""
show introspection commandline

Copyright 2007, Red Hat, Inc
see AUTHORS

This software may be freely redistributed under the terms of the GNU
general public license.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
"""


import optparse
import pprint
import xmlrpclib

from func.overlord import base_command
import show_hardware



class Show(base_command.BaseCommand):
    name = "show"
    usage = "show reports about minion info"
    summary = usage
    subCommandClasses = [show_hardware.ShowHardware]

    socket_timeout = None
    exclude_spec = None
    conffile = None

    def addOptions(self):
        self.parser.add_option("-v", "--verbose", dest="verbose",
                               action="store_true")
        self.parser.add_option('-t', '--timeout', dest="timeout", type="float",
                               help="Set default socket timeout in seconds")
        self.parser.add_option('-e', '--exclude', dest="exclude",
                               help="exclude some of minions",
                               action="store",
                               type="string")
        self.parser.add_option('-c', '--conf', dest="conffile",
                               help="specify an overlord.conf file for func to use")

    def handleOptions(self, options):
        self.options = options

        self.verbose = options.verbose

        if options.timeout:
            self.socket_timeout = options.timeout

        if options.exclude:
            self.exclude_spec = options.exclude

        if options.conffile:
            self.conffile = options.conffile

    def parse(self, argv):
        self.argv = argv

        return base_command.BaseCommand.parse(self, argv)


    def do(self, args):
        pass
