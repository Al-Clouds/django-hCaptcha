import logging

import django

try:
    import json
except ImportError:
    from django.utils import simplejson as json

from django.conf import settings
from django.template.loader import render_to_string
from django.utils.translation import get_language
from django.utils.encoding import force_text

from ._compat import want_bytes, urlencode, Request, urlopen, PY2

logger = logging.getLogger(__name__)

DEFAULT_VERIFY_URL = "https://hcaptcha.com/siteverify"
DEFAULT_WIDGET_TEMPLATE = 'hCaptcha/widget.html'

VERIFY_URL = getattr(settings, "HCAPTCHA_VERIFY_URL",
                     DEFAULT_VERIFY_URL)

WIDGET_TEMPLATE = getattr(settings, "HCAPTCHA_WIDGET_TEMPLATE",
                          DEFAULT_WIDGET_TEMPLATE)


class hCaptchaResponse(object):
    def __init__(self, is_valid, error_codes=None):
        self.is_valid = is_valid
        self.error_codes = error_codes


def displayhtml(site_key, gtag_attrs, js_params):
    """Gets the HTML to display for reCAPTCHA
    site_key -- The public api key provided by Google ReCaptcha
    """

    if 'hl' not in js_params:
        js_params['hl'] = get_language()[:2]

    return render_to_string(
        WIDGET_TEMPLATE,
        {
            'site_key': site_key,
            'js_params': js_params,
            'gtag_attrs': gtag_attrs,
        })


def submit(hcaptcha_response_value, secret_key, remoteip):
    """
    Submits a hCaptcha request for verification. Returns hCaptchaResponse
    for the request
    hcaptcha_response_field -- The value of recaptcha_response_field
    from the form
    secret_key -- your hCaptcha private key
    remoteip -- the user's ip address
    """

    if not (hcaptcha_response_value and len(hcaptcha_response_value)):
        return hCaptchaResponse(
            is_valid=False,
            error_codes=['incorrect-captcha-sol']
        )

    params = urlencode({
        'secret': want_bytes(secret_key),
        'remoteip': want_bytes(remoteip),
        'response': want_bytes(hcaptcha_response_value),
    })

    if not PY2:
        params = params.encode('utf-8')

    req = Request(
        url=VERIFY_URL, data=params,
        headers={
            'Content-type': 'application/x-www-form-urlencoded',
            'User-agent': 'hCaptcha Python'
        }
    )

    httpresp = urlopen(req, params)

    try:
        res = force_text(httpresp.read())
        return_values = json.loads(res)
    except (ValueError, TypeError):
        return hCaptchaResponse(
            is_valid=False,
            error_codes=['json-read-issue']
        )
    except:
        return hCaptchaResponse(
            is_valid=False,
            error_codes=['unknown-network-issue']
        )
    finally:
        httpresp.close()

    return_code = return_values.get("success", False)
    error_codes = return_values.get('error-codes', [])
    logger.debug("%s - %s" % (return_code, error_codes))

    if return_code is True:
        return hCaptchaResponse(is_valid=True)
    else:
        return hCaptchaResponse(is_valid=False, error_codes=error_codes)
