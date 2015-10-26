# coding:utf-8

import optparse
import Queue
import core
import proxy
import re


class Recorder(proxy.BaseSampler):
    request_queue = Queue.Queue()
    filename = ""

    def process(self):
        super(Recorder, self).process()
        Recorder.request_queue.put((self.raw_request, self.raw_response))

    @classmethod
    def process_queue(cls):
        while not Recorder.request_queue.empty():
            rq, rsp = Recorder.request_queue.get()
            try:
                ab = core.ActionBuilder(request=rq, response=rsp)
            except UnicodeDecodeError:
                continue
            save_it = raw_input("Do your want record this action[Y]:%s" % ab._action_dict.url_string)
            if save_it.lower() == "y":
                ab.save()

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-p", "--port", dest="port", type="int", default="12221",
                      help="server port")
    parser.add_option("-d", "--domain", dest="domain", default="0.0.0.0",
                      help="record specific domain")
    (options, args) = parser.parse_args()
    Recorder.host = options.domain
    print "Recording requests to %s" % Recorder.host
    proxy.start_server(port=options.port, sampler=Recorder, callback=Recorder.process_queue)
