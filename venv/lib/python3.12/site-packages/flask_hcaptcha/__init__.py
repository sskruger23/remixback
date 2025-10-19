"""
Flask-hCaptcha

A hCaptcha extension for Flask based on flask-recaptcha+
(c) 2020 Knugi (originally ReCaptcha by Mardix 2015)
"""

flask_available = False
quart_available = False
request = None

try:
    try:
        from flask import request as flask_request
    except ImportError:
        ...
    else:
        flask_available = True

    try:
        from quart import request as quart_request
    except ImportError:
        ...
    else:
        quart_available = True

    if not flask_available and not quart_available:
        raise ImportError

    try:
        from jinja2 import Markup
    except ImportError:
        from markupsafe import Markup
except ImportError:
    print("flask_hcaptcha: Missing dependencies")
    exit()

http_client = None

class BlueprintCompatibility(object):
    site_key = None
    secret_key = None
    custom_data = None


class DEFAULTS(object):
    IS_ENABLED = True
    ASYNC = False


class hCaptcha(object):

    VERIFY_URL = "https://hcaptcha.com/siteverify"
    site_key = None
    secret_key = None
    is_enabled = False

    def __init__(
        self,
        app=None,
        site_key=None,
        secret_key=None,
        is_enabled=True,
        **kwargs
    ):
        self.verify = self.verify_sync
        import requests
        global http_client
        http_client = requests
        if site_key:
            BlueprintCompatibility.site_key = site_key
            BlueprintCompatibility.secret_key = secret_key
            self.is_enabled = is_enabled
        elif app:
            self.init_app(app=app)
        if kwargs:
            BlueprintCompatibility.custom_data = " ".join([f'data-{key}="{value}"' for key, value in kwargs.items()])
             

    def init_app(self, app=None, **kwargs):
        self.__init__(
            site_key=app.config.get("HCAPTCHA_SITE_KEY"),
            secret_key=app.config.get("HCAPTCHA_SECRET_KEY"),
            is_enabled=app.config.get("HCAPTCHA_ENABLED", DEFAULTS.IS_ENABLED),
            **kwargs
        )
        global request, http_client
        if app.config.get("HCAPTCHA_ASYNC", DEFAULTS.ASYNC):
            self.verify = self.verify_async
            try:
                request = quart_request
                import aiohttp
                http_client = aiohttp
            except NameError:
                print(
                    "flask_hcaptcha: Missing dependencies. Did "
                    "you accidentally set HCAPTCHA_ASYNC to True?")
                exit()
        else:
            self.verify = self.verify_sync
            try:
                request = flask_request
            except NameError:
                print("flask_hcaptcha: Missing dependencies")
                exit()

        @app.template_global()
        def hcaptcha_with(**kwargs):
            return Markup(self.get_code(**kwargs))

        @app.context_processor
        def get_code():
            return dict(hcaptcha=Markup(self.get_code()))

    def get_code(self, **kwargs):
        """
        Returns the new hCaptcha code
        :return:
        """
        if kwargs:
            custom_data = " ".join([f'data-{key}="{value}"' for key, value in kwargs.items()])
        else:
            custom_data = BlueprintCompatibility.custom_data
        return "" if not self.is_enabled else ("""
        <script src="https://hcaptcha.com/1/api.js" async defer></script>
        <div class="h-captcha" data-sitekey="{SITE_KEY}" {DATA}></div>
        """.format(
            SITE_KEY=BlueprintCompatibility.site_key,
            DATA=custom_data or ""))

    def verify_sync(self, response=None, remote_ip=None):
        if self.is_enabled:
            data = {
                "secret": BlueprintCompatibility.secret_key,
                "response": response or request.form.get('h-captcha-response'),
                "remoteip": remote_ip or request.environ.get('REMOTE_ADDR')
            }

            r = http_client.post(self.VERIFY_URL, data=data)
            return r.json()["success"] if r.status_code == 200 else False
        return True

    async def verify_async(self, response=None):
        if self.is_enabled:
            data = {
                "secret": BlueprintCompatibility.secret_key,
                "response": response or (await request.form).get(
                    'h-captcha-response',
                    ""
                ),
            }
            async with http_client.ClientSession() as session:
                async with session.post(self.VERIFY_URL, data=data) as resp:
                    result = await resp.json()
                    return result["success"] if resp.status == 200 else False
        else:
            return True
