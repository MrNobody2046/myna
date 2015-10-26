# coding:utf-8
from core import ActionBuilder
if __name__ == "__main__":
    req = """GET /choice?cid=1 HTTP/1.1
Host: push.zhihu.com
Connection: Keep-Alive
User-Agent: Apache-HttpClient/UNAVAILABLE (java 1.4)

"""
    rep = """HTTP/1.1 200 OK
Server: zhihu_nginx
Date: Mon, 24 Aug 2015 06:52:18 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 189
Connection: keep-alive

{"id":1151,"title":"知乎特别推荐","message":"如何评价《三体》获得雨果奖最佳长篇小说？","url":"zhihu://questions/34936428","action":"zhihu.intent.action.PROMOTION"}"""
    ab = ActionBuilder(request=req, response=rep)
    print ab._action_string
    ab.save()
