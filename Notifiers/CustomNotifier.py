import vtrace

class CustomNotifier(vtrace.Notifier):
    # Event is one of the vtrace.NOTIFY_* things listed under vtrace

    def __init__(self, engine):
        self.engine = engine

    def notify(self, event, trace):
        #print "Got event: %d from pid %d" % (event, trace.getPid())
        #print "PID %d thread(%d) got" % (trace.getPid(), trace.getMeta("ThreadId"))

        if event == vtrace.NOTIFY_LOAD_LIBRARY:
            print "vtrace.NOTIFY_LOAD_LIBRARY \t", trace.getMeta('LatestLibrary')
            self.engine.update_cache(trace.getMeta('LatestLibrary'))
        elif event == vtrace.NOTIFY_CREATE_THREAD:
            '''
            Code:
            def attachThread(self, tid, attached=False):
                self.doAttachThread(tid, attached=attached)
                self.setMeta("ThreadId", tid)
                self.fireNotifiers(vtrace.NOTIFY_CREATE_THREAD)
            
            '''
            print "vtrace.NOTIFY_CREATE_THREAD \t", trace.getMeta("ThreadId")
            self.engine.update_tracked_threads(trace.getMeta('ThreadId'), trace.getMeta('Win32Event')['StartAddress'])
            pass
        else:
            print "vtrace.NOTIFY_WTF_HUH?"
