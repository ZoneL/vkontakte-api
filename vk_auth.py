import http.cookiejar
import urllib.request
import urllib.parse
import html.parser

# http://habrahabr.ru/post/143972/
# модуль был написан на основе данной статьи


class FormParser(html.parser.HTMLParser):
    def __init__(self):
        html.parser.HTMLParser.__init__(self)
        self.url = None
        self.params = {}
        self.in_form = False
        self.form_parsed = False
        self.method = "GET"

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "form":
            if self.form_parsed:
                raise RuntimeError("Second form on page")
            if self.in_form:
                raise RuntimeError("Already in form")
            self.in_form = True 
        if not self.in_form:
            return
        attrs = dict((name.lower(), value) for name, value in attrs)
        if tag == "form":
            self.url = attrs["action"] 
            if "method" in attrs:
                self.method = attrs["method"]
        elif tag == "input" and "type" in attrs and "name" in attrs:
            if attrs["type"] in ["hidden", "text", "password"]:
                self.params[attrs["name"]] = attrs["value"] if "value" in attrs else ""

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "form":
            if not self.in_form:
                raise RuntimeError("Unexpected end of <form>")
            self.in_form = False
            self.form_parsed = True

class VKAuthError(Exception):
    def __init__(self, errno, msg):
        self.errno = errno
        self.msg = msg

    def __str__(self):
        return '[{0}] {1}'.format(self.errno, self.msg)

class VKauth:
    valid_scope = {'notify', 'friends', 'photos',
        'audio', 'video', 'docs', 'notes', 'pages',
        'status', 'wall', 'groups', 'messages',
        'notifications', 'stats', 'ads', 'offline'}
    
    def __init__(self, email, password, client_id, permissions):
        """
        VKAuth(email, password, application id, scope)
        Where scope is a list of permissions like ['friends', 'photos']
        If object is successfully initialised, "access token" will
        be in VKAuth.access_token and "user id" in VKAuth.user_id
        raises VKAuthError on errors
        """
        if not isinstance(permissions, list):
            permissions = [permissions]

        for element in permissions:
            if element not in self.valid_scope:
                raise VKAuthError(1, 'invalid scope element: '+element)

            self.__opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                urllib.request.HTTPRedirectHandler())

        try:
            response = self.__opener.open(
                "http://oauth.vk.com/oauth/authorize?" + \
                "redirect_uri=oauth.vk.com/blank.html&response_type=token&" + \
                "client_id={0}&scope={1}&display=wap".format(client_id, ",".join(permissions))
                )
        except urllib.error.URLError as E:
            raise VKAuthError(2, 'internet connection failed')
        except Exception as E:
            raise VKAuthError(0, 'Unhandled exception: '+str(e))

        doc = response.read().decode()
        parser = FormParser()
        parser.feed(doc)
        parser.close()
        if not parser.form_parsed or parser.url is None or "pass" not in parser.params or \
          "email" not in parser.params:
              raise VKAuthError(3, 'wrong response page oO')
        parser.params["email"] = email
        parser.params["pass"] = password
        parser.method = 'POST'
        keys = [ i for i in parser.params]
        for i in keys:
            b = '1'.encode()
            if type(i)!=type(b):
                a = i.encode()
            else: a = i
            if type(parser.params[i])!=type(b):
                parser.params[a] = parser.params[i].encode()
            else:
                parser.params[a] = parser.params[i]
            parser.params.pop(i)

        try:
            response = self.__opener.open(parser.url, urllib.parse.urlencode(parser.params).encode())
        except urllib.error.URLError as E:
            raise VKAuthError(2, 'internet connection failed')
        except Exception as E:
            raise VKAuthError(0, 'Unhandled exception: '+str(e))        

        doc = response.read()
        url = response.geturl()

        if urllib.parse.urlparse(url).path != "/blank.html":
            url = self.__give_access(doc)
        
        if urllib.parse.urlparse(url).path != "/blank.html":
            raise VKAuthError(4, "Invalid email or password")

        def split_key_value(kv_pair):
            kv = kv_pair.split("=")
            return kv[0], kv[1]

        answer = dict(split_key_value(kv_pair) for kv_pair in urllib.parse.urlparse(url).fragment.split("&"))
        if "access_token" not in answer or "user_id" not in answer:
            raise VKAuthError(5, "Missing some values in answer")
        self.access_token = answer["access_token"]
        self.user_id = answer["user_id"]

    def __give_access(self, doc):
        parser = FormParser()
        parser.feed(str(doc))
        parser.close()
        if not parser.form_parsed or parser.url is None:
              raise VKAuthError(4, "Invalid email or password")
        if parser.method == "post":
            response = self.__opener.open(parser.url, urllib.parse.urlencode(parser.params).encode())
        else:
            raise VKAuthError(5, "Method "+parser.method)

        return response.geturl()        

if __name__=='__main__':
    email = input('Email:')
    password = input('Password:')
    client_id = input('Application id:')
    print('Authorising...')
    vk = VKauth(email, password, client_id, ['friends', 'photos'])
    print('\nAccess token: '+vk.access_token) 
    print('User id: '+vk.user_id)