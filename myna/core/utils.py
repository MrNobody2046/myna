# coding:utf-8
import functools
import collections
import json
import copy
import traceback
from random import randint, choice
import contextlib
import sys
from cStringIO import StringIO

import json_schema_generator

"""
TODO: Add cases-insensitive dict
"""


class Random(object):
    @staticmethod
    def string(length):
        c = '0123456789abcdefghijklmnopqrstuvwxyz'
        return ''.join([choice(c) for _ in range(0, length, 2)])

    @staticmethod
    def number(length=11):
        return randint(10 ** length, 10 ** (length + 1) - 1)


class TypeCheck(object):
    is_string = staticmethod(lambda x: isinstance(x, basestring))
    is_int = staticmethod(lambda x: isinstance(x, int))
    is_dict = staticmethod(lambda x: isinstance(x, dict))
    is_list = staticmethod(lambda x: isinstance(x, list))
    is_none = staticmethod(lambda x: x is None)
    is_number = staticmethod(lambda x: isinstance(x, int) or isinstance(x, float))
    is_iterable = staticmethod(lambda x: isinstance(x, collections.Iterable))

    @staticmethod
    def setdefault():
        pass

    @staticmethod
    def required():
        pass

    @staticmethod
    def not_required():
        pass


class DotDict(dict):
    def __getattr__(self, attr):
        return self.get(attr)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    @classmethod
    def convert(cls, data):
        if isinstance(data, dict):
            for k, v in data.items():
                data[k] = cls.convert(v)
            return cls(**data)
        elif isinstance(data, list):
            data[0:] = [cls.convert(v) for v in data]
        return data


def check_result(check_type):
    def _decor(func):
        @functools.wraps(func)
        def _check_res(*args, **kwargs):
            res = func(*args, **kwargs)
            if not isinstance(res, check_type):
                raise Exception("return type check error")
            return res

        return _check_res

    return _decor


def multiple_decor(*decorators):
    def _decor(_wrapped):
        for __decor in decorators:
            _wrapped = __decor(_wrapped)

        def _wrapper(*args, **kwargs):
            return _wrapped(*args, **kwargs)

        return _wrapper

    return _decor

def helper(failback_retv=None, retv_type=type(None), show_msg=True):
    assert type(retv_type) in {type, tuple, set, list}

    def _decor(func):
        @functools.wraps(func)
        def _check_res(*args, **kwargs):

            if args and hasattr(args[0], "__class__"):
                ins = args[0]
            else:
                raise Exception("should be used in class method")
            res = failback_retv
            err = None
            msg = "%s.%s ... ..." % (ins.__class__.__name__, func.__name__)
            try:
                res = func(*args, **kwargs)
                msg += " OK"
            except AssertionError:
                msg += " Failed"
            except Exception, err:
                ins.handle_error(err)
            finally:
                if show_msg:
                    ins.print_msg(msg)
                if err is None and not isinstance(res, retv_type):
                    raise Exception("Return value type check error, should return %s, get %s" % (retv_type, type(res)))
                return res

        return _check_res

    return _decor


def any2dict(obj):
    res = {}
    for k in dir(obj):
        _p = getattr(obj, k)
        if isinstance(_p, (int, float, dict, list, tuple)):
            res[k] = _p
    return res


def __build_self_representation_template(dic, prefix=""):
    for k, v in dic.items():
        if isinstance(v, dict):
            dic[k] = __build_self_representation_template(v, prefix='.'.join((prefix, k)))
        elif isinstance(v, basestring):
            dic[k] = '{{ %s }}' % (prefix.strip(".") + "." + k)
    return dic


@contextlib.contextmanager
def capture():
    out, err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = StringIO(), StringIO()
    try:
        yield sys.stdout, sys.stderr
    except Exception, e:
        traceback.print_exc(file=sys.stderr)
    finally:
        sys.stdout.seek(0)
        sys.stderr.seek(0)
        sys.stdout, sys.stderr = out, err


def traverse_container(data, process_dict=lambda *args: None, process_list=lambda li: li):
    """
    process elements in container (dict and list) with specific function
    :param data:
    :param process_dict:

    :return:
    """
    is_container = lambda x: TypeCheck.is_dict(x) or TypeCheck.is_list(x)
    if TypeCheck.is_dict(data):
        data = data.copy()
        for k, v in data.items():
            if is_container(v):
                data[k] = traverse_container(v, process_dict, process_list)
            else:
                process_dict(data, k, v)
    elif TypeCheck.is_list(data):
        data = process_list(data)
        for v in data:
            if is_container(v):
                traverse_container(v, process_dict, process_list)
    return data


def refine_dict(_dict, remove_none=True, remove_null_str=True):
    """
    Make a data dict looks much simpler, remain first item if the value
    is a list ( assume items in list have the same structure )
    remove keys while those value are None.
    this function can be used to show the representation of the json data.
    :param _dict: dict type
    :return:refined dict
    TODO: check items structure in list, replace string to ""
    """

    def process_dict(data, k, v):
        if TypeCheck.is_none(v) or (TypeCheck.is_string and remove_null_str and v == ""):
            data.pop(k)
        elif TypeCheck.is_int(v):
            data[k] = 0
        elif TypeCheck.is_number:
            data[k] = 0.123401
        elif TypeCheck.is_string(v):
            data[k] = " "

    def process_list(li):
        if li:
            return [li[0]]
        return li

    return traverse_container(_dict, process_dict, process_list)


def refine_json(jstring, **kwargs):
    return json.dumps(refine_dict(json.loads(jstring)), encoding="utf-8", **kwargs)


def generate_jschema(base_obj, to_json=False, remove_id=False):
    base_obj = refine_json(base_obj)
    if not to_json:
        schema = json_schema_generator.SchemaGenerator.from_json(base_obj).to_dict()
    else:
        schema = json_schema_generator.SchemaGenerator.from_json(base_obj).to_json()
    if remove_id:
        schema = remove_id_in_schema(schema)
    return schema


def remove_id_in_schema(schema):
    """
    remove object id in schema dict
    :param schema:dict
    :return:
    """

    def _r(data, k, v):
        if TypeCheck.is_dict(data) and k == "id" and TypeCheck.is_string(v):
            data.pop(k)

    return traverse_container(schema, process_dict=_r)

def getTerminalSize():
    import os
    env = os.environ
    def ioctl_GWINSZ(fd):
        try:
            import fcntl, termios, struct, os
            cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ,
        '1234'))
        except:
            return
        return cr
    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except:
            pass
    if not cr:
        cr = (env.get('LINES', 25), env.get('COLUMNS', 80))

        ### Use get(key[, default]) instead of a try/catch
        #try:
        #    cr = (env['LINES'], env['COLUMNS'])
        #except:
        #    cr = (25, 80)
    return int(cr[1]), int(cr[0])

if __name__ == "__main__":
    with capture() as (out, err):
        print "This line not print"
        # print out.read(), err.read()
    s = [{1: 2, 'asdas': 1123, 'hoh': 1},
         {'ddawwax': 1231231231312},
         {'waawdd': 12312}]
    print traverse_container(s) == s

    print traverse_container(s)
    print getTerminalSize()