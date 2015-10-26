# coding:utf-8
import os
import logging
import logging.handlers
import subprocess
import time


class EasyLogging(object):
    DEFAULT_LOG_PATH = "./"
    SUB_FOLDER = "log"
    FORMAT_A = "%(asctime)s %(filename)s[line:%(lineno)d][pid:%(process)d] %(levelname)-5s %(message)s"
    FORMAT_B = "%(asctime)s %(name)s %(levelname)-6s %(message)s"

    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    DATE_FORMAT_B = "%m%d %H:%M:%S"
    DEFAULT_LEVEL = logging.INFO

    @classmethod
    def set_gmtime(cls):
        logging.Formatter.converter = time.gmtime

    @classmethod
    def set_localtime(cls):
        logging.Formatter.converter = time.localtime

    @classmethod
    def mkdir(cls, path):
        """
        mkdir recursively
        """
        subprocess.check_output(['mkdir', '-p', path])

    @classmethod
    def instance_logger(cls, self, **kwargs):
        """
        eg:
            class A():
                def __init__(self):
                    self.logger = instance_logger(self)
        will create the simple logger for class
        """
        return cls.get_logger(name=self.__class__.__name__, **kwargs)

    @classmethod
    def module_logger(cls):
        module_file = os.path.basename(globals()["__file__"]).split(".")[0]
        logfile = os.path.join(cls.DEFAULT_LOG_PATH, cls.SUB_FOLDER, module_file + '.log')
        return cls.get_logger(name=module_file, filename=logfile)

    @classmethod
    def get_logger(cls, name="easy-logger", level=None, to_console=False, to_file=False, host="", port="", filename="",
                   format="",
                   rotate_by="D1", gmt=True, backupCount=7):
        format = format or cls.FORMAT_A
        level = level or cls.DEFAULT_LEVEL
        if to_file and not filename:
            log_file = "%s.log" % name
            filename = os.path.join(cls.DEFAULT_LOG_PATH, cls.SUB_FOLDER, log_file)
        logger = logging.getLogger(name)
        logger.setLevel(level)
        formatter = logging.Formatter(format, cls.DATE_FORMAT)  # logging.basicConfig(format=fmt,datefmt='%m-%d %H:%M',)
        if gmt:
            formatter.converter = time.gmtime
        if host and port:
            socket_handler = logging.handlers.SocketHandler(host, port)
            socket_handler.setLevel(logging.DEBUG)
            # logging.handlers.SocketHandler('localhost',logging.handlers.DEFAULT_TCP_LOGGING_PORT)
            logger.addHandler(socket_handler)
        if filename:
            log_path = os.path.dirname(filename)
            if log_path:
                if not os.path.exists(log_path):
                    cls.mkdir(log_path)
            when, interval = rotate_by[0], rotate_by[1:]
            file_handler = logging.handlers.TimedRotatingFileHandler(filename, when=when, interval=int(interval),
                                                                     backupCount=backupCount,
                                                                     utc=True)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)
            logger.addHandler(file_handler)
        if to_console:
            console = logging.StreamHandler()
            console.setLevel(level)
            console.setFormatter(formatter)
            logger.addHandler(console)
        # logger = logging.LoggerAdapter(logger,{'ip':address,'user':
        # user_name,'hostname':hostname,})
        return logger


class _Log(object):
    def __init__(self):
        self.logger = EasyLogging.instance_logger(self, to_console=True)


if __name__ == "__main__":

    gen_log = logging.getLogger("tornado.general")
    gen_log.addHandler(logging.StreamHandler())
    gen_log.error("xx")
    logger = EasyLogging.module_logger()
    l = _Log()
    l.logger.error("hello world")
    l.logger.info("hello world")
    for i in range(10):
        logger.info("info")
        logger.debug("debug")
        logger.error("gmt error")
    EasyLogging.set_localtime()
    for i in range(10):
        logger.info("local info")
        logger.error("local error")
