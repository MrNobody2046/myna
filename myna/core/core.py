# coding:utf-8
import re
import json
import pprint
import inspect
import urlparse
import warnings
import collections

from StringIO import StringIO
from unittest import TestCase
from BaseHTTPServer import BaseHTTPRequestHandler as BHRH
from httplib import HTTPResponse

import jsonschema
import json_schema_generator
import jinja2

import Cookie
import requests
import elg

import utils

logger = elg.EasyLogging.get_logger("myna.core", to_console=True, to_file=False)

retv_check = lambda tp: utils.helper(retv_type=tp, show_msg=False)


class Settings(object):
    default_request_method = "get"
    timeout = 60

    def load(self):
        pass


class CoreBase(object):
    def print_msg(self, msg):
        logger.info(msg)

    def handle_error(self, ecpt):
        logger.exception(ecpt)


class Response(CoreBase):
    ResponseFields = ['content', 'status_code',
                      'headers', 'url',
                      'history', 'encoding',
                      'reason', 'cookies',
                      'elapsed', ]

    def __init__(self, resp):
        """
        load response from requests.response
        :param resp:
        :return:
        """
        self._response = resp
        self.cookies = dict(resp.cookies)
        self.status_code = resp.status_code
        self.headers = dict(resp.headers)  # CaseInsensitiveDict
        for k, v in self.headers.items():
            self.headers[k.lower()] = v  # deprecated
        self.url = resp.url
        self.history = resp.history
        self.encoding = resp.encoding
        self.reason = resp.reason
        self.elapsed = 10.0
        self.content = resp._content

    def pprint(self):
        return {k: getattr(self, k, None) for k in self.ResponseFields}

    def cookies(self):
        return dict(self._response.cookies)

    def status_code(self):
        return self._response.status_code

    def headers(self):
        return dict(self._response.headers)


class Request(CoreBase):
    has_body = False

    def __init__(self, action_request, sender=requests.session()):
        self._request = action_request
        self.sender = sender
        if action_request.type == "raw":
            pass  # process  raw http request bytes
        if action_request.type not in ["get"]:
            self.has_body = True
        self.method = action_request.method.lower()
        self._raw_response = None

    def format_requests(self):
        self.url = self.format_url(self._request.url)
        self.headers = self.format_headers(self._request.headers)
        self.headers["content-type"] = self.content_type
        self.body = self.format_body()
        self.cookies = self.format_cookies(self._request.cookies)

    @staticmethod
    @utils.multiple_decor(utils.check_result(basestring))
    def format_url(url):
        """
        if action.request.url is string,  parse it to segments
        if action.request.url is segments , join it to url string
        :param url:
        :return:
        """
        if utils.TypeCheck.is_dict(url):
            url = urlparse.urlunparse(
                (url.get("scheme", "http"),
                 url.netloc, url.get("path", ""),
                 url.param, url.query,
                 url.fragment)
            )
        return url

    @staticmethod
    @utils.multiple_decor(utils.check_result(dict))
    def format_cookies(cookies):
        """
        format cookies return cookies dict
        :param cookies:
        :return:
        """
        cookies = cookies or {}
        if not isinstance(cookies, dict):
            _cookie = Cookie.SimpleCookie()
            _cookie.load(cookies)
            cookies = {k: morsel.value for k, morsel in _cookie.items()}
        return cookies

    @staticmethod
    @utils.multiple_decor(utils.check_result(dict))
    def format_headers(headers):
        headers = headers or {}
        if utils.TypeCheck.is_string(headers):
            headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers))
        return headers

    @retv_check((basestring, dict))
    def format_body(self):
        """
        """
        data = self._request.body.get("data", "")
        if self.has_body and data:
            if isinstance(data, basestring):
                pass  # raw string
            else:
                data = dict(**data)
        return data

    @property
    @retv_check(basestring)
    def content_type(self):
        return self._request.body.get("content-type", "")

    @utils.helper()
    def prepare_request(self, prepare=None):
        self.format_requests()
        if prepare and hasattr(prepare, "__call__"):
            prepare()
            self.format_requests()

    @retv_check(Response)
    def send_request(self):
        self._raw_response = self.sender.request(self.method,
                                                 self.url,
                                                 headers=self.headers,
                                                 cookies=self.cookies,
                                                 data=self.body,
                                                 allow_redirects=self._request.allow_redirects or False,
                                                 timeout=Settings.timeout)
        return Response(self._raw_response)


class ValidatorMod(type):
    def __new__(mcs, name, bases, attrs):
        attrs.update({v: (lambda _f: lambda *args, **kwargs: not _f(*args, **kwargs))(attrs[k]) for k, v in
                      attrs["validator_pairs"].items()})

        return type.__new__(mcs, name, bases, attrs)


class Validator(CoreBase, TestCase):
    """
    TODO : Mixin with TestCase
    """
    __metaclass__ = ValidatorMod
    # generator validator pairs(negative judgment)
    logger = elg.EasyLogging.get_logger("validator", to_console=True, to_file=False)

    assertions = "assertions"
    json_schema = "json_schema"

    validator_pairs = {
        "response_is_json": "response_is_not_json",
        "response_is_ok": "response_not_ok",
        # call with parametes
        "contains_string": "not_contains_string",
        "equal_to": "not_equal_to",
        "almost_equal_to": "must_not_equal_to",
        "content_type_is": "content_type_is_not",
        "time_is_less": "time_is_more_than",
        "status_code_is": "status_code_is_not",
    }

    def __init__(self, request, response, validations={}):
        self.request = request  # from action.request
        self.response = response  # ?
        if self.response is None:
            return
        self.validations = validations
        self.assertions = self.validations.pop(self.assertions, [])
        self.json_schema = self.validations.pop(self.json_schema, {})
        self.run()

    def run(self):
        self.base_check()
        for i in self.assertions:
            astmt = getattr(self, i, None)
            if astmt:
                self.single_test(astmt)
        for k, v in self.validations.items():
            stms = getattr(self, k, None)
            if stms:
                self.single_test(stms, v)
            else:
                warnings.warn("Invalid method %s" % k)

    def single_test(self, func, *args, **kwargs):
        msg = ["Case check : ", func.__name__.replace("_", " "), ]
        try:
            if args:
                msg.append(str(args[0]))
            func(*args, **kwargs)
            msg.append("... ... OK")
        except AssertionError:
            msg.append("... ... Failed")
        except Exception, e:
            msg.append(" ... ... Error:%r" % e)
        finally:
            logger.info(' '.join(msg))

    def load(self):
        self.json_instance = json.loads(self.response.content)

    @utils.helper()
    def base_check(self):
        assert isinstance(self.response.content, basestring)
        assert isinstance(self.response.headers, dict)

    def response_is_json(self):
        try:
            self.load()
        except:
            raise AssertionError("response content is not json")

    def response_is_ok(self):
        assert self.response.reason.lower() == 'ok'

    def status_code_is(self, expect_code):
        if isinstance(expect_code, (list, tuple, set)):
            assert self.response.status_code in expect_code
        else:
            assert self.response.status_code == expect_code

    def contains_string(self, string):
        assert self.response.content.find(string) != -1

    def equal_to(self, string):
        self.assertEqual(self.response.content, string)

    def almost_equal_to(self, string, similarity=0.9):
        self.assertAlmostEqual(self.response.content, string)

    def content_type_is(self, type_is):
        self.assertAlmostEqual(self.response.headers.get("content-type", ""), type_is)

    def time_is_less(self, time_in_ms):
        self.assertLessEqual(time_in_ms, self.response.elapsed)

    def json_schema_validate(self):
        try:
            self.load()
            if self.json_schema:
                jsonschema.validate(instance=self.json_instance, schema=self.json_schema)
        except Exception, e:
            raise AssertionError("Json schema validation failed")

    @classmethod
    def get_empty_validations(cls):
        _li = []
        _di = {}
        for k, v in cls.validator_pairs.items():
            if k.find("response_is") != -1:
                _li.append(v)
            else:
                _di[k] = None

        __validations = {cls.assertions: _li}
        __validations.update(_di)
        __validations[cls.json_schema] = None
        return utils.DotDict.convert(__validations)

    @classmethod
    def get_validations_by_response(cls, content):
        """
        Generate json schema according to response json data
        :param content:
        :return:
        """
        validations = cls.get_empty_validations()
        try:
            jdata = utils.refine_json(content)
            validations[cls.json_schema] = json_schema_generator.SchemaGenerator.from_json(jdata).to_dict()
        except Exception, e:
            warnings.warn("Json schema generate failed: %r" % e)
        return validations

    def handle_error(self, err):
        if isinstance(err, AssertionError):
            pass
        else:
            self.logger.exception(err)


class Action(CoreBase):
    logger = logger

    _url = _cookies = _headers = ""
    direct_map_to_action = ["encoding", "content", "status_code", "ok", "link", "url", "reason"]
    convert_dict_map_to_aciton = ["headers", "cookies"]
    lbd_map_to_action = [
        lambda r: r.elapsed.total_seconds()
    ]

    def __init__(self, action, sender=requests.session()):
        self.action = utils.DotDict.convert(action)
        self.request = Request(self.action.request, sender=sender)
        self.response = None
        self.validations = self.action.validations

        self.action.name = self.action.name if self.action.name else self.untitled()
        self.errors = []
        self.run()

    def untitled(self):
        return "untitled_%s" % utils.Random.string(4)

    def run(self):
        pre = None
        self.prepare()
        self.response = self.request.send_request()
        self.action.response = self.response
        self.finish_action()
        self.validation()

    @property
    def name(self):
        return self.action.name

    @utils.helper()
    def prepare(self):
        if self.action.prepare and hasattr(self.action.prepare, "__call__"):
            pre = lambda: self.action.prepare(self)
            self.request.prepare_request(prepare=pre)

    @utils.helper()
    def finish_action(self):
        getattr(self.action.finish, "__call__", lambda x: None)(self)

    def validation(self):
        Validator(self.request, self.response, self.validations)

    def handle_error(self, e):
        self.logger.exception(e)

    __call__ = run


class Templates(object):
    code_template = jinja2.Template("""
    {
        "name": "{{ action.name }}",
        "url_string": "{{ action.url_string }}",
        "prepare": "{{ action.prepare }}",
        "finish": "{{ action.finish }}",
        "request": {
            "allow_redirects": "{{ action.request.allow_redirects }}",
            "auth": "{{ action.request.auth }}",
            "body": {
                "content-type": "{{ action.request.body["content-type"] }}",
                "data": "{{ action.request.body.data }}"
            },
            "cookies": { {% for k,v in action.request.cookies.items() %}
                "{{ k }}": "{{ v }}",{% endfor %}
            },
            "headers": { {% for k,v in action.request.headers.items() %}
                "{{ k }}": "{{ v }}",{% endfor %}
            },
            "method": "{{ action.request.method }}",
            "type": "{{ action.request.type }}",
            "url": { {% for k,v in action.request.url.items() %}
                "{{ k }}": "{{ v }}",{% endfor %}
            }
        },
        "response":{
            "headers": { {% for k,v in action.response.headers.items() %}
                "{{ k }}": "{{ v }}",{% endfor %}
            },
            "content": "{{ action.response.content }}",
        },
        "validations": {
            "assertions":[{% for item in action.validations.pop("assertions") %}
                    "{{ item }}",{% endfor %}
                ],
            "json_schema" : {{ action.validations.pop("json_schema") }},
            {% for k,v in action.validations.items() %}
                "{{ k }}": "{{ v }}",{% endfor %}
        },
    }""")

    auth = {

    }

    request_containor = {
        "type": "formated",
        "method": "{method}",
        "allow_redirects": "False",
        "url": {"scheme": "{pr.scheme}",
                "netloc": "{pr.netloc}",
                "path": "{pr.path}",
                "query": "{pr.query}",
                "fragment": "{pr.fragment}",
                "params": "{pr.params}"},
        "headers": {

        },
        "cookies": {

        },
        "body": {
            "content-type": "",
            "value": ""
        },
        "auth": {

        },

    }

    printer = pprint.PrettyPrinter(indent=1)

    @classmethod
    def format_item(cls, obj):
        return cls.printer.pformat(obj)


class ActionEncoder(json.JSONEncoder):
    def default(self, obj):
        if getattr(obj, "__call__", ""):
            encoded_object = inspect.getsource(obj).strip().split("#")[0].split(":", 1)[1].strip()
        else:
            encoded_object = json.JSONEncoder.default(self, obj)
        return encoded_object


class ActionBuilder(BHRH):
    """
    Build action case from raw http request bytes.
    parse_request --> request -->
        build_action --> action dict(_action_dict) --> filling into template(_string_action)
            --> save in file
    TODO: add response parse
        automatically generate response validations
    TODO: daa empty action template
    """
    request_version = None
    pattern = '.*?{func_name}\"\:\ ([\S\s]*?)\,\ ?$'

    def __init__(self, request="", response=""):
        self.rfile = StringIO(request)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
        """
        parse_request will eval
        self.command, self.path, self.request_version
        """
        self.parser_result = urlparse.urlparse(self.path)
        self._resp = response  # raw http response bytes
        self.response = build_response(self._resp) if self._resp else None
        self._action_dict = self.build_action(return_json_string=False)
        self._action_string = self.format_action(self._action_dict)

    def save(self, filename=""):
        """
        save action string to code file
        :param filename:
        :return:
        """
        if not filename:
            filename = self._action_dict["name"] + ".py"
            filename = re.sub(r'[\\/:"*?<>|]+', "", filename)
        self.save_codes(self._action_string, filename=filename)

    @classmethod
    def load_action_from_raw(cls, action):
        action = json.loads(action)
        for k in ("finish", "prepare"):
            if action.get(k):
                action[k] = eval(action[k])
        return action

    @classmethod
    def eval_lambda_in_action_template(cls, action):
        for func_name in ("prepare", "finish"):
            sub_str = re.compile(cls.pattern.format(func_name=func_name), re.M | re.I).findall(action)[0]
            action = action.replace(sub_str, sub_str.strip('"'))
        return action

    @classmethod
    def save_codes(cls, codes, filename):
        with open(filename, "w") as wf:
            wf.write(codes)

    @classmethod
    def format_action(cls, action):
        """

        :param action:
        :return:string
        """
        name = action["name"]
        action = Templates.code_template.render(action=action)
        action = cls.eval_lambda_in_action_template(action)
        lines = action.split("\n")
        lines = [l[4:] for l in lines]
        lines[0] = name + " = " + "\\"
        return '\n'.join(lines)

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

    def build_action(self, return_json_string=True):
        """
        Format request and response then packaging them in action
        :param return_json_string: if True will return string
        :return: utils.DotDict or string
        """
        __request = Templates.request_containor.copy()
        method = self.command
        url = self.build_url()
        cookies = self.build_cookies()
        auth = self.build_authorization()
        headers = self.build_headers()
        body = self.build_body()
        lcs = locals()
        for k in __request.keys():
            if lcs.has_key(k):
                __request[k] = lcs[k]
        __action = collections.OrderedDict()
        __action["name"] = self.build_action_name()
        __action["url_string"] = self.build_url_string()
        __action["prepare"] = "lambda action: None"
        __action["request"] = __request
        __action["response"] = self.build_response()
        if self.response:
            validations = Validator.get_validations_by_response(self.response.read())
            validations[Validator.json_schema] = Templates.format_item(validations[Validator.json_schema])
            _schema_lines = validations[Validator.json_schema].split("\n")
            _schema_lines = [" " * 20 + line for line in _schema_lines]
            _schema_lines.insert(0, "")
            validations[Validator.json_schema] = "\n".join(_schema_lines)
            __action["validations"] = validations
        else:
            __action["validations"] = Validator.get_empty_validations()
            self.response.seek(0)
        __action["when_finish"] = __action["prepare"]
        if return_json_string:
            return json.dumps(__action, cls=ActionEncoder, indent=4)
        return utils.DotDict.convert(__action)

    __call__ = build_action

    def build_url(self):
        return {"scheme": self.parser_result.scheme, "netloc": self.parser_result.netloc,
                "path": self.parser_result.path, "query": self.parser_result.query,
                "fragment": self.parser_result.fragment, "params": self.parser_result.params}

    def build_url_string(self):
        return self.path

    def build_action_name(self):
        netloc = self.parser_result.netloc.replace(".", "")
        an = "_".join((self.command, netloc, self.parser_result.path)).lower()
        return re.sub(r'[\\/:"*?<>|]+', "", an)

    def build_cookies(self):
        cookie_str = self.headers.dict.get("cookie", "")
        sc = Cookie.SimpleCookie(cookie_str)
        cookie = {}
        for k, v in sc.viewitems():
            cookie[k] = v.value
        return cookie

    def build_authorization(self):
        authorization = self.headers.dict.get("authorization", "")
        return authorization

    def build_headers(self):
        return {k: v for k, v in self.headers.items() if k not in {"cookie", "authorization"}}

    def build_body(self):
        if self.command.upper() in {"DELETE", "GET"}:
            body_type = ""
            body_value = ""
        else:
            body_type = self.headers.dict.get("content-type")
            body_value = self.get_body()
        return {"content-type": body_type, "data": body_value}

    def build_response(self):
        res = {
            "headers": {},
            "content": ""
        }
        try:
            res["headers"] = dict(self.response.getheaders())
            res["content"] = ""  # http_respone.read()
        except Exception, e:
            print "save response error:", e
        finally:
            return res

    def build_json_schema(self, content):
        pass

    def get_body(self):
        self.rfile.seek(0)
        bf = self.rfile.read()
        self.rfile.seek(0)
        p = bf.find('\r\n\r\n')
        if p >= 0:
            return bf[p + 4:]


class FakeSocket(StringIO):
    def makefile(self, *args, **kwargs):
        self.seek(0)
        return self


def build_response(resp):
    resp = HTTPResponse(FakeSocket(resp))
    resp.begin()
    return resp


settigs = {

    "break_action_when_failed": True,  # if set true, will stop at any exception
    "host": ""  #

}


class ActionFlow(object):
    def __init__(self):
        pass
