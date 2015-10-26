# coding:utf-8
import json
import inspect
import urlparse
import re
from BaseHTTPServer import BaseHTTPRequestHandler as BHRH
from httplib import HTTPResponse
from StringIO import StringIO

from core import DotDict
import Cookie
import jinja2
import core


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
            {% for k,v in action.validations.items() %}
                "{{ k }}": "{{ v }}",{% endfor %}
        },
    }""")

    auth = {

    }

    request_containor = {
        "type": "{formated}",
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

    action_containor = {
        "name": "{name}",
        "prepare": "lambda action: None",  # calculator signatures here
        "request": request_containor,
        "response": "",
        "validation": {
            "json_validator": "",
            "contain": "xxx",
            "status_code": 200},
        "finish": "lambda action: None",  # process response(if have) here
        "break_if_failed": ""  # only used in flow

    }


class ActionEncoder(json.JSONEncoder):
    def default(self, obj):
        if getattr(obj, "__call__", ""):
            encoded_object = inspect.getsource(obj).strip().split("#")[0].split(":", 1)[1].strip()
        else:
            encoded_object = json.JSONEncoder.default(self, obj)
        return encoded_object


class ActionBuilder(BHRH):
    """
    Build action case from raw http request, use
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
        self._resp = response
        self._action_dict = self.build_action(return_json_string=False)
        self._string_action = self.format_action(self._action_dict)

    def save(self, filename=""):
        if not filename:
            filename = self._string_action["name"] + ".py"
            filename = re.sub(r'[\\/:"*?<>|]+', "", filename)
        self.save_codes(self._string_action, filename=filename)

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
        :return: DotDict or string
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
        __request["type"] = "formated"
        __action = Templates.action_containor.copy()
        __action["request"] = __request
        __action["response"] = self.build_response()
        __action["name"] = self.build_action_name()
        __action["url_string"] = self.build_url_string()
        __action["validations"] = core.Validator.get_empty_validations()
        if return_json_string:
            return json.dumps(__action, cls=ActionEncoder, indent=4)
        return DotDict.convert(__action)

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
            http_respone = build_response(self._resp)
            res["headers"] = dict(http_respone.getheaders())
            res["content"] = ""  # http_respone.read()
        except Exception, e:
            print "save response error:", e
        finally:
            return res

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


if __name__ == "__main__":
    pass
