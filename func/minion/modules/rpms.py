# Copyright 2007, Red Hat, Inc
# Michael DeHaan <mdehaan@redhat.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import func_module
import rpm

class RpmModule(func_module.FuncModule):

    def inventory(self, flatten=True):
        """
        Returns information on all installed packages.
        By default, 'flatten' is passed in as True, which makes printouts very clean in diffs
        for use by func-inventory.  If you are writting another software application, using flatten=False will
        prevent the need to parse the returns.
        """
        ts = rpm.TransactionSet()
        mi = ts.dbMatch()
        results = []
        for hdr in mi:
            name = hdr['name']
            epoch = hdr['epoch']
            if epoch is None:
                epoch = 0
            version = hdr['version']
            release = hdr['release']
            arch = hdr['arch']
            if flatten:
                results.append("%s %s %s %s %s" % (name,epoch,version,release,arch))
            else:
                results.append([name,epoch,version,release,arch])
        return results
