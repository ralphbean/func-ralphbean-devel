##
## Copyright 2007, Red Hat, Inc
## see AUTHORS
##
## This software may be freely redistributed under the terms of the GNU
## general public license.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
##

import inspect

from func import logger
from func.config import read_config
from func.commonconfig import FuncdConfig
from func.minion.func_arg import * #the arg getter stuff

class FuncModule(object):

    # the version is meant to
    version = "0.0.0"
    api_version = "0.0.0"
    description = "No Description provided"

    def __init__(self):

        config_file = '/etc/func/minion.conf'
        self.config = read_config(config_file, FuncdConfig)
        self.__init_log()
        self.__base_methods = {
            # __'s so we don't clobber useful names
            "module_version" : self.__module_version,
            "module_api_version" : self.__module_api_version,
            "module_description" : self.__module_description,
            "list_methods"       : self.__list_methods,
            "get_method_args"    : self.__get_method_args,
        }

    def __init_log(self):
        log = logger.Logger()
        self.logger = log.logger

    def register_rpc(self, handlers, module_name):
        # add the internal methods, note that this means they
        # can get clobbbered by subclass versions
        for meth in self.__base_methods:
            handlers["%s.%s" % (module_name, meth)] = self.__base_methods[meth]

        # register our module's handlers
        for name, handler in self.__list_handlers().items():
            handlers["%s.%s" % (module_name, name)] = handler

    def __list_handlers(self):
        """ Return a dict of { handler_name, method, ... }.
        All methods that do not being with an underscore will be exposed.
        We also make sure to not expose our register_rpc method.
        """
        handlers = {}
        for attr in dir(self):
            if self.__is_public_valid_method(attr):
                handlers[attr] = getattr(self, attr)
        return handlers

    def __list_methods(self):
        return self.__list_handlers().keys() + self.__base_methods.keys()

    def __module_version(self):
        return self.version

    def __module_api_version(self):
        return self.api_version

    def __module_description(self):
        return self.description

    def __is_public_valid_method(self,attr):
        if inspect.ismethod(getattr(self, attr)) and attr[0] != '_' and\
                attr != 'register_rpc':
                    return True
        return False

    def __get_method_args(self):
        """
        Gets arguments with their formats according to ArgCompatibility
        class' rules.

        @return : dict with args or Raise Exception if something wrong
        happens
        """
        tmp_arg_dict = self.__register_method_args()

        #if it is not implemeted then return empty stuff 
        if not tmp_arg_dict:
            return {}

        #see if user tried to register an not implemented method :)
        for method in tmp_arg_dict.keys():
            if not hasattr(self,method):
                raise NonExistingMethodRegistered("%s is not in %s "%(method,self.__class__.__name__))
        
        #create argument validation instance
        self.arg_comp = ArgCompatibility(tmp_arg_dict)
        #see if the options that were used are OK..
        self.arg_comp.validate_all()

        return tmp_arg_dict 

    def __register_method_args(self):
        """
        That is the method where users should override in their
        modules according to be able to send their method arguments
        to the Overlord. If they dont have it nothing breaks
        just that one in the base class is called

        @return : empty {}
        """

        # to know they didnt implement it
        return {}
    
    def __is_all_args_registered(self,name):
        """
        Checks if module writer has made some mistakes about 
        argument registering

        @param name: the name of the method with arguments registered in it
        @retun : dict(name:[arg1,arg2...]) or {}
        """
         #FIXME tobe rewritten
        if name in self.__base_methods.keys():
            return {}
        
        #tests showed that sometimes happens
        if not hasattr(self,name):
            return {}

        if not self.__is_public_valid_method(name):
            return {}

        arg_names = inspect.getargspec(getattr(self,name))
        #arg_names[0] is argument names
        #arg_names[1] is *arg
        #arg_names[2] is **kwarg
        #arg_names[3] are defaults

        name_dict =[other_args for other_args in arg_names[1:3] if other_args]
        arg_names = arg_names[0] or []
        
        #if we have self lets remove it 
        for rem in arg_names:
            if rem=="self":
                arg_names.remove(rem)
                break
        
        final_dict={}
        final_dict[name]=arg_names+name_dict
        return final_dict
