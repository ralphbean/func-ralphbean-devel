## func
##
## filetracker
##  maintains a manifest of files of which to keep track
##  provides file meta-data (and optionally full data) to func-inventory
##
## (C) Vito Laurenza <vitolaurenza@gmail.com>
## + Michael DeHaan <mdehaan@redhat.com>
##
## This software may be freely redistributed under the terms of the GNU
## general public license.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
##

# func modules
import func_module

# other modules
from stat import *
import fnmatch
import glob
import os
import md5
import shelve

# defaults
OLD_CONFIG_FILE='/etc/func/modules/filetracker.conf'
CONFIG_FILE='/etc/func/modules/filetracker.shelf'
F_ATTR_NAMES = ['mode', 'mtime', 'uid', 'gid', 'md5sum']

class FileTracker(func_module.FuncModule):

    version = "0.0.2"
    api_version = "0.0.2"
    description = "Maintains a manifest of files to keep track of."

    def __migrate(self):
        """
        Migrate from a v0.0.1 filehash to a v0.0.2 filehash
        """
        filehash = {}
        if os.path.exists(OLD_CONFIG_FILE):
            config = open(CONFIG_FILE, "r")
            data   = config.read()
            lines  = data.split("\n")
            for line in lines:
                tokens = line.split(None)
                if len(tokens) < 2:
                    continue
                scan_mode = tokens[0]
                path = " ".join(tokens[1:])
                if str(scan_mode).lower() == "0":
                    scan_mode = 0
                else:
                    scan_mode = 1
            filehash[path] = {'scan_mode' : scan_mode }
        else:
            raise IOError, "no such file %s" % OLD_CONFIG_FILE
        # Save the loaded hash out to the new format
        self.__save(filehash)
        # Get rid of the old config file so we never run this method again
        os.remove(OLD_CONFIG_FILE)

    #==========================================================

    def __load(self):
        """
        Parse file and return data structure.
        """

        if os.path.exists(OLD_CONFIG_FILE):
            self.__migrate()

        filehash = {}
        if os.path.exists(CONFIG_FILE):
            d = shelve.open(CONFIG_FILE)
            filehash = d['filehash']
            d.close()
        return filehash

    #==========================================================

    def __save(self, filehash):
        """
        Write data structure to file.
        """

        d = shelve.open(CONFIG_FILE)
        d['filehash'] = filehash
        d.close()

    #==========================================================

    def track(self, file_name_globs,
              full_scan=0, recursive=0, files_only=0, ignore=''):
        """
        Adds files to keep track of.
        file_names can be a single filename, a list of filenames, a filename glob
           or a list of filename globs
        full_scan implies tracking the full contents of the file, defaults to off
        recursive implies tracking the contents of every subdirectory
        files_only implies tracking files that are files (not directories)
        ignore is a list of file properties to ignore
            valid values are any of F_ATTR_NAMES
        """

        # ignore might be a list or a str.  make it a list and remove ''
        if isinstance(ignore, str):
            ignore = ignore.split(',')
        ignore = [attr for attr in ignore if not attr is '']

        # check that no values passed in `ignore` are invalid
        for attr in ignore:
            if not attr in F_ATTR_NAMES:
                msg = "ignore: '%s' is not in %s" % (attr, str(F_ATTR_NAMES))
                raise ValueError, msg

        filehash = self.__load()
        filenameglobs = []

        # accept a single string or list
        filenameglobs.append(file_name_globs)
        if type(file_name_globs) == type([]):
            filenameglobs = file_name_globs

        def _recursive(original_filenames):
            for filename in original_filenames:
                for (dir, subdirs, subfiles) in os.walk(filename):
                    for subdir in subdirs:
                        yield "%s/%s" % (dir, subdir)
                    for subfile in subfiles:
                        yield "%s/%s" % (dir, subfile)

        # expand everything that might be a glob to a list
        # of names to track
        for filenameglob in filenameglobs:
            filenames = glob.glob(filenameglob)
            if recursive:
                filenames += _recursive(filenames)
            if files_only:
                filenames = [f for f in filenames if os.path.isfile(f)]
            for filename in filenames:
                filehash[filename] = {'full_scan': full_scan, 'ignore': ignore}
        self.__save(filehash)
        return 1

    #==========================================================

    def untrack(self, file_name_globs):
        """
        Stop keeping track of a file.
        file_name_globs can be a single filename, a list of filenames, a filename glob
           or a list of filename globs
        This routine is tolerant of most errors since we're forgetting about the file anyway.
        """

        filehash = self.__load()
        filenames = filehash.keys()
        matched = 0
        for filename in filenames:
            for file_name_glob in file_name_globs:
                if fnmatch.fnmatch(filename, file_name_glob):
                    matched = 1
                    del filehash[filename]
        self.__save(filehash)
        return matched

    #==========================================================

    def inventory(self, flatten=1, checksum_enabled=1):
        """
        Returns information on all tracked files
        By default, 'flatten' is passed in as True, which makes printouts very clean in diffs
        for use by func-inventory.  If you are writting another software application, using flatten=False will
        prevent the need to parse the returns.
        """

        # XMLRPC feeds us strings from the CLI when it shouldn't
        flatten = int(flatten)
        checksum_enabled = int(checksum_enabled)

        filehash = self.__load()

        # we'll either return a very flat string (for clean diffs)
        # or a data structure
        if flatten:
            results = ""
        else:
            results = []

        filenames = sorted(filehash.keys())
        for file_name in file_names:
            config = filehash[file_name]
            scan_type = config.get('scan_type', 0)
            ignore = config.get('ignore', [])

            if not os.path.exists(file_name):
                if flatten:
                    results = results + "%s: does not exist\n" % file_name
                else:
                    results.append("%s: does not exist\n" % file_name)
                continue

            this_result = []

            # ----- define how we collect metadata
            def _determine_hash(file_name, filestat):
                hash = "N/A"
                if not os.path.isdir(file_name) and checksum_enabled:
                    sum_handle = open(file_name)
                    hash = self.__sumfile(sum_handle)
                    sum_handle.close()
                return hash

            f_attr_names = [n for n in F_ATTR_NAMES if n not in ignore]
            f_attr_functions = {
                'mode' : lambda n, s : s[ST_MODE],
                'mtime' : lambda n, s : s[ST_MTIME],
                'uid' : lambda n, s : s[ST_UID],
                'gid' : lambda n, s : s[ST_GID],
                'md5sum' : _determine_hash,
            }

            # ----- collect the metadata
            f_attrs = {}
            filestat = os.stat(file_name)
            for f_attr in f_attr_names:
                f_attr_function = f_attr_functions[f_attr]
                f_attrs[f_attr] = f_attr_function(file_name, filestat)

            # ------ what we return depends on flatten
            if flatten:
                attr_str = "  ".join(
                    ["=".join([n, f_attrs[n]]) for n in f_attr_names])
                this_result = "%s:  %s" % (file_name, attr_str)
            else:
                this_result = [file_name] + [f_attrs[n] for n in f_attr_names]

            # ------ add on file data only if requested
            if scan_type != 0 and os.path.isfile(file_name):
                tracked_file = open(file_name)
                data = tracked_file.read()
                if flatten:
                    this_result = this_result + "*** DATA ***\n" + data + "\n*** END DATA ***\n\n"
                else:
                    this_result.append(data)
                tracked_file.close()

            if os.path.isdir(file_name):
                if not file_name.endswith("/"):
                    file_name = file_name + "/"
                files = glob.glob(file_name + "*")
                if flatten:
                    this_result = this_result + "*** FILES ***\n" + "\n".join(files) + "\n*** END FILES ***\n\n"
                else:
                    this_result.append({"files" : files})

            if flatten:
                results = results + "\n" + this_result
            else:
                results.append(this_result)


        return results

    #==========================================================

    def grep(self, word):
        """
        Some search utility about tracked files
        """
        results = {self.inventory:[]}
        tracked_files = self.inventory()

        if type(tracked_files) == str and tracked_files.lower().find(word)!=-1:
            results[self.inventory].append(tracked_files)

        else:
            for res in tracked_files:
                if res.lower().find(word)!=-1:
                    results[self.inventory].append(res)

        return results
    grep = func_module.findout(grep)


    def __sumfile(self, fobj):
        """
        Returns an md5 hash for an object with read() method.
        credit: http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/266486
        """

        m = md5.new()
        while True:
            d = fobj.read(8096)
            if not d:
                break
            m.update(d)
        return m.hexdigest()

    def register_method_args(self):
        """
        Implementing the argument getter part
        """

        return {
                'inventory':{
                    'args':{
                        'flatten':{
                            'type':'boolean',
                            'optional':True,
                            'default':True,
                            'description':"Show info in clean diffs"
                            },
                        'checksum_enabled':{
                            'type':'boolean',
                            'optional':True,
                            'default':True,
                            'description':"Enable the checksum"
                            }
                        },
                    'description':"Returns information on all tracked files"
                    },
                'track':{
                    'args':{
                        'file_name_globs':{
                            'type':'string',
                            'optional':False,
                            'description':"The file name to track (full path)"
                            },
                        'full_scan':{
                            'type':'int',
                            'optional':True,
                            'default':0,
                            'description':"The 0 is for off and 1 is for on"
                            },
                        'recursive':{
                            'type':'int',
                            'optional':True,
                            'default':0,
                            'description':"The 0 is for off and 1 is for on"
                            },
                        'files_only':{
                            'type':'int',
                            'optional':True,
                            'default':0,
                            'description':"Track only files (not dirs or links)"
                            },
                        'ignore':{
                            'type':'string',
                            'optional':True,
                            'default':'',
                            'description':"Comma-separated list of file attributes to ignore",
                            }
                        },
                    'description':"Adds files to keep track of"
                    },
                'untrack':{
                    'args':{
                        'file_name_globs':{
                            'type':'string',
                            'optional':False,
                            'description':"The file name to untrack (full path)"
                            }
                        },
                    'description':"Remove the track from specified file name"
                    }
                }
