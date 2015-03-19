# -*- coding: utf-8 -*-

"""
Cookie handling module.
"""

import logging
import os

import requests

from six.moves import StringIO
from six.moves import http_cookiejar as cookielib
from .define import AUTH_URL, CLASS_URL, AUTH_REDIRECT_URL, PATH_COOKIES
from .utils import mkdir_p


# Monkey patch cookielib.Cookie.__init__.
# Reason: The expires value may be a decimal string,
# but the Cookie class uses int() ...
__orginal_init__ = cookielib.Cookie.__init__


def __fixed_init__(self, version, name, value,
                   port, port_specified,
                   domain, domain_specified, domain_initial_dot,
                   path, path_specified,
                   secure,
                   expires,
                   discard,
                   comment,
                   comment_url,
                   rest,
                   rfc2109=False,
                   ):
    if expires is not None:
        expires = float(expires)
    __orginal_init__(self, version, name, value,
                     port, port_specified,
                     domain, domain_specified, domain_initial_dot,
                     path, path_specified,
                     secure,
                     expires,
                     discard,
                     comment,
                     comment_url,
                     rest,
                     rfc2109=False,)

cookielib.Cookie.__init__ = __fixed_init__


class ClassNotFound(BaseException):
    """
    Raised if a course is not found in Coursera's site.
    """


class AuthenticationFailed(BaseException):
    """
    Raised if we cannot authenticate on Coursera's site.
    """


def login(session, class_name, username, password):
    """
    Login on accounts.coursera.org with the given credentials.
    This adds the following cookies to the session:
        sessionid, maestro_login, maestro_login_flag
    """

    try:
        session.cookies.clear('.coursera.org')
    except KeyError:
        pass

    # Hit class url to obtain csrf_token
    class_url = CLASS_URL.format(class_name=class_name)
    r = requests.get(class_url, allow_redirects=False)

    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logging.error(e)
        raise ClassNotFound(class_name)

    csrftoken = r.cookies.get('csrf_token')

    if not csrftoken:
        raise AuthenticationFailed('Did not recieve csrf_token cookie.')

    # Now make a call to the authenticator url.
    headers = {
        'Cookie': '__204u=9997994733-1418049002166; __204r=http%3A%2F%2Fwww.mooc.cn%2Fcourse%2F1574.html; '
                  'ab-experiments-user=upcoming_window_leading2%2Cupcoming_window_trailing2%2Cnew_records_'
                  'page_eocs_banner%2Cin_class_qqs%2Cin_class_qqs_button; ab-experiments-session=specializations_'
                  'landing_swap%2Csignup_title_copy%2Csignup_description_copy%2Cspecializations_cover_banner%2Chomepage'
                  '_user_count%2Csigtrack_course_page_button; __400v=6578dde9-10aa-4415-bf72-9c00683340c7; __utmt=1; '
                  '__400vt=1418914985294; CAUTH=; maestro_login_flag=; maestro_login=; __utma=158142248.1741834991.'
                  '1418049006.1418910586.1418913751.15; __utmb=158142248.47.10.1418913751; __utmc=158142248; '
                  '__utmz=158142248.1418657195.8.2.utmcsr=coursera.org|utmccn=(referral)|utmcmd=referral|utmcct=/; '
                  'csrftoken=TjrgmhXgWEU46RFK8sZwgiS9; csrf2_token_l6pgZCrT=CedPXBnxoHZrv1TFp5YhiT0H',
        'Referer': 'https://accounts.coursera.org/signin',
        'X-CSRFToken': 'TjrgmhXgWEU46RFK8sZwgiS9',
        'Host':'accounts.coursera.org',
        'Origin':'https://accounts.coursera.org',
        'Referer':'https://accounts.coursera.org/signin?post_redirect=https%3A%2F%2Fwww.coursera.org%2Faccount%2Flogout',
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) '
                     'Chrome/39.0.2171.95 Safari/537.36',

    }

    data = {
        'email': username,
        'password': password,
        'webrequest': 'true'
    }

    r = session.post(AUTH_URL, data=data,
                     headers=headers, allow_redirects=False)
    try:
        logging.debug('login page%s'%r)
        r.raise_for_status()

    except requests.exceptions.HTTPError:
        raise AuthenticationFailed('Cannot login on accounts.coursera.org.')

    logging.info('Logged in on accounts.coursera.org.')


def down_the_wabbit_hole(session, class_name):
    """
    Authenticate on class.coursera.org
    """

    auth_redirector_url = AUTH_REDIRECT_URL.format(class_name=class_name)
    r = session.get(auth_redirector_url)
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError:
        raise AuthenticationFailed('Cannot login on class.coursera.org.')


def _get_authentication_cookies(session, class_name,
                                username, password):
    try:
        session.cookies.clear('class.coursera.org', '/' + class_name)
    except KeyError:
        pass

    down_the_wabbit_hole(session, class_name)

    enough = do_we_have_enough_cookies(session.cookies, class_name)

    if not enough:
        raise AuthenticationFailed('Did not find necessary cookies.')


def get_authentication_cookies(session, class_name, username, password):
    """
    Get the necessary cookies to authenticate on class.coursera.org.

    To access the class pages we need two cookies on class.coursera.org:
        csrf_token, session
    """

    # First, check if we already have the .coursera.org cookies.
    if session.cookies.get('CAUTH', domain=".coursera.org"):
        logging.debug('Already logged in on accounts.coursera.org.')
    else:
        login(session, class_name, username, password)

    _get_authentication_cookies(
        session, class_name, username, password)

    logging.info('Found authentication cookies.')


def do_we_have_enough_cookies(cj, class_name):
    """
    Checks whether we have all the required cookies
    to authenticate on class.coursera.org.
    """
    domain = 'class.coursera.org'
    path = "/" + class_name

    return cj.get('csrf_token', domain=domain, path=path) is not None


def validate_cookies(session, class_name):
    """
    Checks whether we have all the required cookies
    to authenticate on class.coursera.org. Also check for and remove
    stale session.
    """
    if not do_we_have_enough_cookies(session.cookies, class_name):
        return False

    url = CLASS_URL.format(class_name=class_name) + '/class'
    r = session.head(url, allow_redirects=False)

    if r.status_code == 200:
        return True
    else:
        logging.debug('Stale session.')
        try:
            session.cookies.clear('.coursera.org')
        except KeyError:
            pass
        return False


def make_cookie_values(cj, class_name):
    """
    Makes a string of cookie keys and values.
    Can be used to set a Cookie header.
    """
    path = "/" + class_name

    cookies = [c.name + '=' + c.value
               for c in cj
               if c.domain == "class.coursera.org"
               and c.path == path]

    return '; '.join(cookies)


def find_cookies_for_class(cookies_file, class_name):
    """
    Return a RequestsCookieJar containing the cookies for
    .coursera.org and class.coursera.org found in the given cookies_file.
    """

    path = "/" + class_name

    def cookies_filter(c):
        return c.domain == ".coursera.org" \
            or (c.domain == "class.coursera.org" and c.path == path)

    cj = get_cookie_jar(cookies_file)

    new_cj = requests.cookies.RequestsCookieJar()
    for c in filter(cookies_filter, cj):
        new_cj.set_cookie(c)

    return new_cj


def load_cookies_file(cookies_file):
    """
    Loads the cookies file.

    We pre-pend the file with the special Netscape header because the cookie
    loader is very particular about this string.
    """

    cookies = StringIO()
    cookies.write('# Netscape HTTP Cookie File')
    cookies.write(open(cookies_file, 'rU').read())
    cookies.flush()
    cookies.seek(0)
    return cookies


def get_cookie_jar(cookies_file):
    cj = cookielib.MozillaCookieJar()
    cookies = load_cookies_file(cookies_file)

    # nasty hack: cj.load() requires a filename not a file, but if I use
    # stringio, that file doesn't exist. I used NamedTemporaryFile before,
    # but encountered problems on Windows.
    cj._really_load(cookies, 'StringIO.cookies', False, False)

    return cj


def get_cookies_cache_path(username):
    return os.path.join(PATH_COOKIES, username + '.txt')


def get_cookies_from_cache(username):
    """
    Returns a RequestsCookieJar containing the cached cookies for the given
    user.
    """
    path = get_cookies_cache_path(username)
    logging.debug('cookie path:%s'%path)
    cj = requests.cookies.RequestsCookieJar()
    try:
        cached_cj = get_cookie_jar(path)
        for cookie in cached_cj:
            cj.set_cookie(cookie)
        logging.debug(
            'Loaded cookies from %s', get_cookies_cache_path(username))
    except IOError:
        pass

    return cj


def write_cookies_to_cache(cj, username):
    """
    Saves the RequestsCookieJar to disk in the Mozilla cookies.txt file
    format.  This prevents us from repeated authentications on the
    accounts.coursera.org and class.coursera.org/class_name sites.
    """
    mkdir_p(PATH_COOKIES, 0o700)
    path = get_cookies_cache_path(username)
    cached_cj = cookielib.MozillaCookieJar()
    for cookie in cj:
        cached_cj.set_cookie(cookie)
    cached_cj.save(path)


def get_cookies_for_class(session, class_name,
                          cookies_file=None,
                          username=None,
                          password=None):
    """
    Get the cookies for the given class.
    We do not validate the cookies if they are loaded from a cookies file
    because this is intented for debugging purposes or if the coursera
    authentication process has changed.
    """
    if cookies_file:
        cookies = find_cookies_for_class(cookies_file, class_name)
        session.cookies.update(cookies)
        logging.info('Loaded cookies from %s', cookies_file)
    else:
        cookies = get_cookies_from_cache(username)
        session.cookies.update(cookies)
        if validate_cookies(session, class_name):
            logging.info('Already authenticated.')
        else:
            get_authentication_cookies(session, class_name, username, password)
            write_cookies_to_cache(session.cookies, username)
