GET_ = \
    {
        "finish": lambda action: None,
        "name": "GET_",
        "prepare": lambda action: None,
        "request": {
            "allow_redirects": "False",
            "auth": "",
            "body": {
                "content-type": "",
                "value": ""
            },
            "cookies": {
            },
            "headers": {
                "host": "www.github.com",
                "proxy-connection": "Keep-Alive",
                "accept": "*/*",
            },
            "method": "GET",
            "type": "formated",
            "url": {
                "scheme": "http",
                "params": "",
                "path": "/",
                "fragment": "",
                "query": "",
                "netloc": "www.github.com",
            }
        },
        "response": "",
        "validations": {
            "assertions": [
                "response_is_json",
                "response_is_ok"
            ]
        }
    }



from myna.core import Action

if __name__ == "__main__":
    ac = Action(GET_)
    ac()