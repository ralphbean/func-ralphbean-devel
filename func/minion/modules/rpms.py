# Copyright 2007, Red Hat, Inc
# Michael DeHaan <mdehaan@redhat.com>
# Copyright 2009
# Milton Paiva Neto <milton.paiva@gmail.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import func_module

class RpmModule(func_module.FuncModule):

    version = "0.0.1"
    api_version = "0.0.1"
    description = "RPM related commands."

    def inventory(self, flatten=True):
        """
        Returns information on all installed packages.
        By default, 'flatten' is passed in as True, which makes printouts very
        clean in diffs for use by func-inventory.  If you are writting another
        software application, using flatten=False will prevent the need to
        parse the returns.
        """
        return self.glob('', flatten)

    def grep(self, word):
        """
        Grep some info from packages we got from
        inventory especially
        """
        results = {self.inventory:[]}
        inventory_res = self.inventory()

        for res in inventory_res:
            if res.lower().find(word)!= -1:
                results[self.inventory].append(res)
        return results

    grep = func_module.findout(grep)

    def verify(self, pattern='', flatten=True):
        """
        Returns information on the verified package(s).
        """
        results = []
        for rpm in self.glob(pattern, False):
            name = rpm[0]

            yb = yum.YumBase()
            pkgs = yb.rpmdb.searchNevra(name)
            for pkg in pkgs:
                errors = pkg.verify()
                for fn in errors.keys():
                    for prob in errors[fn]:
                        if flatten:
                            results.append('%s %s %s' % (name, fn, prob.message))
                        else:
                            results.append([name, fn, prob.message])
        return results

    def glob(self, pattern, flatten=True):
        """
        Return a list of installed packages that match a pattern
        """
        import rpm
        ts = rpm.TransactionSet()
        mi = ts.dbMatch()
        results = []
        if not mi:
            return results
        if (pattern != ''):
            mi.pattern('name', rpm.RPMMIRE_GLOB, pattern)
        for hdr in mi:
            name = hdr['name']
            # not all packages have an epoch
            epoch = (hdr['epoch'] or 0)
            version = hdr['version']
            release = hdr['release']
            # gpg-pubkeys have no arch
            arch = (hdr['arch'] or "")
            if flatten:
                # flatten forms a simple text list separated by spaces
                results.append("%s %s %s %s %s" % (name, epoch, version,
                                                   release, arch))
            else:
                # Otherwise we return it as a list
                results.append([name, epoch, version, release, arch])
        results.sort()
        return results


    def register_method_args(self):
        """
        Implementing the method argument getter
        """
        return {
                'inventory':{
                    'args':{
                        'flatten':{
                            'type':'boolean',
                            'optional':True,
                            'default':True,
                            'description':"Print clean in difss"
                            }
                        },
                    'description':"Returns information on all installed packages"
                    },
                'verify':{
                    'args':{
                        'flatten':{
                            'type':'boolean',
                            'optional':True,
                            'default':True,
                            'description':"Print clean in difss"
                            }
                        },
                    'description':"Returns information on the verified package(s)"
                    },
                'glob':{
                    'args':{
                        'pattern':{
                            'type':'string',
                            'optional':False,
                            'description':"The glob packet pattern"
                            },
                        'flatten':{
                            'type':'boolean',
                            'optional':True,
                            'default':True,
                            'description':"Print clean in difss"
                                }
                        },
                    'description':"Return a list of installed packages that match a pattern"
                    }
                }
