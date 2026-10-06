#    Back In Time
#    Copyright (C) 2008-2017 Oprea Dan, Bart de Koning, Richard Bailey, Germar Reitze
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


import os
import pluginmanager
import gettext

_=gettext.gettext


class NotifyPlugin( pluginmanager.Plugin ):
    def __init__( self ):
        self.user = ''

        try:
            self.user = os.getlogin()
        except:
            pass

        if not self.user:
            try:
                user = os.environ['USER']
            except:
                pass

        if not self.user:
            try:
                user = os.environ['LOGNAME']
            except:
                pass

    def init( self, snapshots ):
        return True

    def is_gui( self ):
        return True

    def on_process_begins( self ):
        pass

    def on_process_ends( self ):
        pass

    def on_error( self, code, message ):
        return

    def on_new_snapshot( self, snapshot_id, snapshot_path ):
        return

    def on_message( self, pid, pname, severity, text, seconds ):
        if 1 == severity:
            command_line = "notify-send "
            if seconds > 0:
                command_line = command_line + " -t %s" % (1000 * seconds)

            heading = "Back In Time (%s) : %s" % (self.user, pname)
            text = text.replace("\n", ' ')
            text = text.replace("\r", '')

            command_line = command_line + " \"%s\" \"%s\"" % (heading, text)
            print(command_line)
            os.system(command_line)
        return
