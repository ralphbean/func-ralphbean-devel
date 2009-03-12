#That module is going to contain the parts that
#hide (proxies) the Overlord and Minion work

from func.overlord.client import Overlord,CommandAutomagic
from func.minion.facts.query import FuncLogicQuery

class OverlordQueryProxy(object):
    """
    That class will encapsulate the Overlord
    class and do the stuff invisibly to the
    user
    """
    def __init__(self,*args,**kwargs):
        """
        You can pass progrmatically a overlord object or
        you can construct one as you do normally ...
        """
        #some initialization stuff here ...
        if kwargs.has_key('overlord_obj'):
            self.overlord = kwargs['overlord_obj']
        else:
            self.overlord = Overlord(*args,**kwargs)
        
        fact_query = None
        if kwargs.has_key('fact_query'):
            fact_query = kwargs['fact_query']
        self.fact_query = fact_query or FuncLogicQuery()
        
        #print "These are : ",self.overlord
        #print "These are : ",self.fact_query

    def serialize_query(self):
        """
        That part hides the complexity of internal data
        in self.fact_query and passes it over the silent
        network wire :)
        """
        return [self.fact_query.connector,self.__recurse_traverser(self.fact_query.q)]

    def __recurse_traverser(self,q_object):
        """
        Recuresvily traverse the Q object and return
        back a list like structure which is ready tobe
        sent ...
        """
        results=[] 
        for n in q_object.children:
            if not type(n) == tuple and not type(n) == list:
                if n.negated:
                    results.append(["NOT",[n.connector,self.__recurse_traverser(n)]])
                else:
                    results.append([n.connector,self.__recurse_traverser(n)])
            else:
                #here you will do some work
                for ch in xrange(0,len(n),2):
                    results.append(n[ch:ch+2])

        return results
    
    def __getattribute__(self,name):
        """
        Making it kind of proxy object to the Q object
        """
        try:
            #print "What we get lol ",name
            return object.__getattribute__(self, name)
        except AttributeError:
            #it doesnt have that method so we
            #should send method to another place
            if not self.fact_query:
                try:
                    return object.__getattribute__(self.overlord,name)
                except AttributeError:
                    return self.overlord.__getattr__(name)
            else:
                #create the serialized thing to be sent with all of
                #them as a first argument so other side gateway can
                #take and process it before real method is theree
                if hasattr(self.overlord,name):
                    try:
                        return object.__getattribute__(self.overlord,name)
                    except AttributeError:
                        return CommandAutomagic(self, [name], self.overlord.nforks)
    
    def filter(self,*args,**kwargs):
        """
        Filter The facts and doesnt call
        the minion directly just gives back a 
        reference to the same object
        """
        self.fact_query=self.fact_query.filter(*args,**kwargs)
        #give back the reference
        return self

    def exclude(self,*args,**kwargs):
        """
        Exclude the things from set
        and give back a reference 
        """
        self.fact_query=self.fact_query.exclude(*args,**kwargs)
        #give back the reference
        return self

    def set_complexq(self,q_object,connector=None):
        self.fact_query=self.fact_query.set_compexq(q_object,connector)
        #give back the reference
        return self
    
    def job_status(self, jobid,with_facts=False):
        """
        Overriden because we need to get results which
        only has True result from their fact queries,that
        was the reason we created the facts ...
        """
        status,async_result = self.overlord.job_status(jobid)
        if not self.fact_query:
            #that will use the default overlord job_status
            return (status,async_result)
        else:
            return (status,self.display_active(async_result,with_facts))



    def display_active(self,result,with_facts=False):
        """
        When we got all of the resultsfrom minions we may need
        to display only the parts that match the facts query
        """
        final_display = {}
        for minion_name,minion_result in result.iteritems():
            #CAUTION ugly if statements around :)
            if type(minion_result) == list and type(minion_result[0]) == dict and minion_result[0].has_key('__fact__') :
                if minion_result[0]['__fact__'][0] == True:
                    if with_facts:
                        final_display[minion_name] = minion_result
                    else:
                        final_display[minion_name] = minion_result[1:][0]
            else:
                return result

        return final_display

