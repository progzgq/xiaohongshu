import collections
from urllib.parse import quote, urlencode

from api.utils.common import hash_md5
from api.utils.http.request import HttpRequest

host = 'https://www.xiaohongshu.com'

session_id = 'session.1546427716649918680'
user_token = '64b70404139fe65d5a79fd7aed77ab38'
user_id = '558c0049e58d13527f77c692'

device_id = 'aaeec521-4084-aefe-aceb-812820cebb71'
model = 'Huawei xxx'



def get_sign(pay_load, device_id):
    form_str = ''
    keyset = [key for key in pay_load.keys()]
    keyset = sorted(keyset)
    for key in keyset:
        form_str = f'{form_str}{key}={pay_load.get(key,"")}'
    form_str = quote(form_str, encoding='utf-8')
    barr = form_str.encode()
    bytes = device_id.encode()
    stringbuild2 = ''
    i = 0
    for b2 in barr:
        stringbuild2 += str(b2 ^ bytes[i])
        i = (i + 1) % len(bytes)
    map = ''
    a2 = hash_md5(stringbuild2)
    map += a2
    map += bytes.decode()
    map = hash_md5(map)
    return map


def build_header(device_id, user_token=''):
    header = {
        'device_id': device_id,
        'X-Tingyun-Id': 'LbxHzUNcfig;c=2;r=1705493984;u=9d0a763bb38e9df0a6ce014d33f0348a53e70ac0da77fc830b5eb37306716c035211d1046ef031743705c7d47b843db5::BC6C6793D57FA9C7',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 6.0.1; Le X820 Build/FEXCNFN6003009092S) Resolution/1440*2560 Version/5.35.0 Build/5350161 Device/(LeMobile;Le X820) NetType/WiFi',
        'Authorization': user_token
    }
    return header


def get_verify_code(phone):
    url = f'{host}/api/sns/v1/system_service/vfc_code'
    pay_load = collections.OrderedDict()
    pay_load['zone'] = '86'
    pay_load['phone'] = phone
    pay_load['type'] = 'login'
    pay_load['platform'] = 'android'
    pay_load['deviceId'] = device_id
    pay_load[
        'device_fingerprint'] = '20181226153752d53f41865ece9d8144d7a0c833ae8a2201de47c5a9062bb8'
    pay_load[
        'device_fingerprint1'] = '20181226153752d53f41865ece9d8144d7a0c833ae8a2201de47c5a9062bb8'
    pay_load['versionName'] = '5.35.0'
    pay_load['channel'] = 'YingYongBaofufei'
    pay_load['sid'] = ''
    pay_load['lang'] = 'zh-Hans'
    pay_load['t'] = '1546395258'
    sign = get_sign(pay_load, device_id)
    pay_load['sign'] = sign
    header = build_header(device_id)
    resp = HttpRequest().execute(url, 'xhs', method='get', uid=1,
                                 params=pay_load,
                                 headers=header)
    return resp.get('success', False)


def verify_code_login(username, code):
    url = f'{host}/api/sns/v1/system_service/check_code'
    pay_load = collections.OrderedDict()
    pay_load['zone'] = '86'
    pay_load['phone'] = username
    pay_load['code'] = code
    pay_load['platform'] = 'android'
    pay_load['deviceId'] = device_id
    pay_load[
        'device_fingerprint'] = '20181226153752d53f41865ece9d8144d7a0c833ae8a2201de47c5a9062bb8'
    pay_load[
        'device_fingerprint1'] = '20181226153752d53f41865ece9d8144d7a0c833ae8a2201de47c5a9062bb8'
    pay_load['versionName'] = '5.35.0'
    pay_load['channel'] = 'YingYongBaofufei'
    pay_load['sid'] = ''
    pay_load['lang'] = 'zh-Hans'
    pay_load['t'] = '1546396124'
    sign = get_sign(pay_load, device_id)
    pay_load['sign'] = sign
    header = build_header(device_id)
    resp = HttpRequest().execute(url, 'xhs', method='get', uid=1,
                                 params=pay_load,
                                 headers=header)
    code_token = resp.get('data', {}).get('token')
    if not code_token:
        raise Exception('验证码校验失败')
    url = f'{host}/api/sns/v4/user/login/code'
    pay_load = collections.OrderedDict()
    pay_load['phone'] = username
    pay_load['imei'] = '862177030478427'
    pay_load['zone'] = '86'
    pay_load['type'] = 'phone'
    pay_load['mobile_token'] = code_token
    pay_load['android_id'] = '659cef5bdcc685b3'
    pay_load['platform'] = 'android'
    pay_load['deviceId'] = device_id
    pay_load[
        'device_fingerprint'] = '20181226153752d53f41865ece9d8144d7a0c833ae8a2201de47c5a9062bb8'
    pay_load[
        'device_fingerprint1'] = '20181226153752d53f41865ece9d8144d7a0c833ae8a2201de47c5a9062bb8'
    pay_load['versionName'] = '5.35.0'
    pay_load['channel'] = 'YingYongBaofufei'
    pay_load['sid'] = ''
    pay_load['lang'] = 'zh-Hans'
    pay_load['t'] = '1546396224'  # f'{arrow.now().timestamp}'
    sign = get_sign(pay_load, device_id)
    pay_load['sign'] = sign
    header = build_header(device_id)
    header.update({'Content-Type': 'application/x-www-form-urlencoded'})
    resp = HttpRequest().execute(url, 'xhs', method='post', uid=1,
                                 data=urlencode(pay_load),
                                 headers=header)
    user_token = resp.get('data', {}).get('user_token')
    session_id = resp.get('data', {}).get('user_tosecure_sessionken', '')[6:]
    print(user_token)
    print(session_id)
    return user_token, session_id


def login(username, pwd):
    '''
    :param username:
    :param pwd:
    :return:
    '''
    url = f'{host}/api/sns/v4/user/login/password'
    pay_load = collections.OrderedDict()
    pay_load['phone'] = username
    pay_load['password'] = hash_md5(pwd)
    pay_load['imei'] = '862177030478427'
    pay_load['zone'] = '86'
    pay_load['type'] = 'phone'
    pay_load['android_id'] = '659cef5bdcc685b3'
    pay_load['platform'] = 'android'
    pay_load['deviceId'] = device_id
    pay_load[
        'device_fingerprint'] = '20181226153752d53f41865ece9d8144d7a0c833ae8a2201de47c5a9062bb8'
    pay_load[
        'device_fingerprint1'] = '20181226153752d53f41865ece9d8144d7a0c833ae8a2201de47c5a9062bb8'
    pay_load['versionName'] = '5.35.0'
    pay_load['channel'] = 'YingYongBaofufei'
    pay_load['sid'] = ''
    pay_load['lang'] = 'zh-Hans'
    pay_load['t'] = '1546413304'  # f'{arrow.now().timestamp}'
    sign = get_sign(pay_load, device_id)
    pay_load['sign'] = sign
    header = build_header(device_id)
    header.update({'Content-Type': 'application/x-www-form-urlencoded',
                   'shield': 'a68d9f4594a7f1151a87f18b256902647c8baa759f2299650bdaa80c1d3563ce'})
    resp = HttpRequest().execute(url, 'xhs', method='post', uid=1,
                                 data=urlencode(pay_load),
                                 headers=header)
    user_token = resp.get('data', {}).get('user_token')
    session_id = resp.get('data', {}).get('secure_session', '')[6:]
    userid = resp.get('data', {}).get('userid')
    ret = {
        'user_token': user_token,
        'session_id': session_id,
        'userid': userid
    }
    print(ret)
    return ret


def get_user_by_keyword(username, keyword, page):
    url = f'{host}/api/sns/v9/search/notes'
    pay_load = collections.OrderedDict()
    pay_load['keyword'] = '酒店'
    pay_load['filters'] = ''
    pay_load['sort'] = ''
    pay_load['page'] = page
    pay_load['page_size'] = 20
    pay_load['source'] = 'explore_feed'
    pay_load['search_id'] = 'C5EF17DE33E583EAFD64323D5581CC68'
    pay_load['api_extra'] = ''
    pay_load['platform'] = 'android'
    pay_load['deviceId'] = device_id
    pay_load[
        'device_fingerprint'] = '20181226153752d53f41865ece9d8144d7a0c833ae8a2201de47c5a9062bb8'
    pay_load[
        'device_fingerprint1'] = '20181226153752d53f41865ece9d8144d7a0c833ae8a2201de47c5a9062bb8'
    pay_load['versionName'] = '5.35.0'
    pay_load['channel'] = 'YingYongBaofufei'
    pay_load['sid'] = session_id
    pay_load['lang'] = 'zh-Hans'
    pay_load['t'] = '1546400566'
    sign = get_sign(pay_load, device_id)
    pay_load['sign'] = sign
    header = build_header(device_id, user_token=session_id)
    header.update({
        'shield_id': '7879199b2f7e994775adb3f5a6c0bcf6616c5258f57d2b1bdd2386b59115993e'})
    resp = HttpRequest().execute(url, 'xhs', method='get', uid=1,
                                 params=pay_load,
                                 headers=header)
    return resp.get('data', {}).get('notes')

