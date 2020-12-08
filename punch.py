# -*-coding:utf-8-*-
import requests
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
import base64
import json
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
import random
import getpass
import yaml
import sys
import uuid
import traceback

"""
基于python3.7开发的日常打卡脚本，每天到点自动打卡并发送微信消息通知
author:Ben
"""

requests.packages.urllib3.disable_warnings()

scheduler = BlockingScheduler()

API_BASE_URL = 'xxx'

WX_NOTIFY_BASE_URL = 'http://wxpusher.zjiecode.com/api'

PUNCH_TYPE = (1, 2)

PUNCH_DATA = {'latitude': 'xxx', 'longitude': 'xxx', 'address': 'xxx',
              'punchType': PUNCH_TYPE[0], 'deviceNo': 'xxx'}

HEADERS = {}

"""
rsa public key
"""
PUB_KEY = '\n'.join([
    '-----BEGIN PUBLIC KEY-----',
    '{pub_key}',
    '-----END PUBLIC KEY-----'
])

APP_TOKEN = 'AT_xxx'

PUNCH_DETAIL_URL = 'xxx'

signal_mr = 0
signal_af = 0

try:
    with open('./conf.yaml', 'r', encoding='utf-8') as stream:
        config_data = yaml.load(stream, Loader=yaml.FullLoader)
        if not config_data:
            print('缺少配置，请检查配置文件内容')
            sys.exit()
except FileNotFoundError as exc:
    print('未找到配置文件，请检查yaml配置文件')
    sys.exit()


def cut_str(data, length):
    """cut str from length"""
    return [data[i:i + length] for i in range(0, len(data), length)]


def encrypt(public_key, message):
    """rsa加密，通常对加密结果进行base64编码"""
    cipher = Cipher_pkcs1_v1_5.new(public_key)
    cipher_text = base64.b64encode(cipher.encrypt(message))
    return cipher_text


def decrypt(rsakey, encrypt_text):
    """rsa解密"""
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    return cipher.decrypt(base64.b64decode(encrypt_text), '')


# (pubkey, privkey) = rsa.newkeys(1024)


# def gen_pub_key():
#     with open('public.pem', 'w+') as f:
#         f.write(pubkey.save_pkcs1().decode())


def load_pub_key_frompem():
    """load public key from pem file"""
    with open('public.pem', 'r') as f:
        pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(f.read().encode('utf-8'))
        return pubkey


def load_pub_key_fromstr(data):
    """load public key from str"""
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(data.encode('utf-8'))
    return pubkey


def get_encrypt_data():
    """get server defined key"""
    url = f'{API_BASE_URL}/Encrypt'
    r = requests.post(url, verify=False)
    return r.text


def login_with_crypto_rsa(*args, **kwargs):
    """login with Crypto rsa"""
    login_user_name = args[0][0]
    login_user_password = args[0][1]
    public_key_data = get_encrypt_data()
    new_key_data = '\n'.join(cut_str(public_key_data, 64))
    public_key_data = PUB_KEY.replace('{pub_key}', new_key_data)
    public_key = RSA.importKey(public_key_data)
    rsa_password = encrypt(public_key, login_user_password)
    data = {'userPhone': login_user_name, 'loginMethod': 'pwd',
            'loginPwd': rsa_password.decode()}

    url = f'{API_BASE_URL}/Login'
    r = requests.post(url, json.dumps(data), verify=False)
    return r.text


def login_with_rsa(*args, **kwargs):
    """login with rsa"""
    login_user_name = config_data.get('login_name')
    login_user_password = config_data.get('password')

    data = get_encrypt_data()
    new_key_data = '\n'.join(cut_str(data, 64))
    public_key_data = PUB_KEY.replace('{pub_key}', new_key_data)
    public_key_data = load_pub_key_fromstr(public_key_data)
    rsa_password = rsa.encrypt(login_user_password.encode(), public_key_data)
    rsa_password = base64.b64encode(rsa_password)
    data = {'userPhone': login_user_name, 'loginMethod': 'pwd',
            'loginPwd': rsa_password.decode()}

    url = f'{API_BASE_URL}/Login'
    r = requests.post(url, json.dumps(data), verify=False)
    res_txt = r.text
    if not res_txt:
        return {'code': '0', 'msg': '登录失败'}

    login_result = json.loads(res_txt)
    msg = login_result.get('msg')
    print(msg)
    data = login_result.get('data')
    if not data:
        return {'code': '0', 'msg': '未获取到登录信息'}

    return data


# 上午打卡
def punch_morning(*args, **kwargs):
    """morning punch"""
    global signal_mr
    scheduler.remove_job('morning_job')

    try:
        if signal_mr == 1:
            data = login_with_rsa(args, kwargs)
            if data.get('code') == '0':
                return data
            uid = data.get('uid')
            token = data.get('token')
            HEADERS['token'] = token
            PUNCH_DATA['uid'] = uid
            PUNCH_DATA['punchType'] = PUNCH_TYPE[0]

            url = f'{API_BASE_URL}/PunchFace'
            r = requests.post(url, PUNCH_DATA, headers=HEADERS, files=dict(gg='gg'), verify=False)
            if not r.text:
                return {'code': '0', 'msg': '上班打卡失败!!'}
            result_data = json.loads(r.text)

            # view_url = PUNCH_DETAIL_URL.replace('#ut#', token).replace('#uid#', uid)
            msg = result_data.get('msg') + '\n' + result_data.get('data').get('timeStr')
            print(msg)
            push_data = {
                'appToken': APP_TOKEN,
                'content': msg,
                'contentType': 1,
                'uids': [
                    config_data.get('wx_notify_uid')
                ],
                'url': ''
            }
            url = f'{WX_NOTIFY_BASE_URL}/send/message'
            requests.post(url, json=push_data)
    except Exception as exc:
        traceback.format_exc(exc)
    finally:
        morning_minute = random.randint(40, 58)
        morning_second = random.randint(0, 59)
        job_0 = CronTrigger(day_of_week='0-4', hour=8, minute=morning_minute, second=morning_second)
        scheduler.add_job(punch_morning, job_0, id='morning_job')
        signal_mr = 1
        print(job_0)


# 下午打卡
def punch_afternoon(*args, **kwargs):
    """afternoon punch"""
    global signal_af
    scheduler.remove_job('afternoon_job')

    try:
        if signal_af == 1:
            data = login_with_rsa(args, kwargs)
            uid = data.get('uid')
            token = data.get('token')
            HEADERS['token'] = token
            PUNCH_DATA['uid'] = uid
            PUNCH_DATA['punchType'] = PUNCH_TYPE[1]

            url = f'{API_BASE_URL}/PunchFace'
            r = requests.post(url, PUNCH_DATA, headers=HEADERS, files=dict(gg='gg'), verify=False)
            if not r.text:
                return {'code': '0', 'msg': '下班打卡失败!!'}
            result_data = json.loads(r.text)

            # view_url = PUNCH_DETAIL_URL.replace('#ut#', '').replace('#uid#', uid)

            msg = result_data.get('msg') + '\n' + result_data.get('data').get('timeStr')
            print(msg)
            push_data = {
                'appToken': APP_TOKEN,
                'content': msg,
                'contentType': 1,
                'uids': [
                    config_data.get('wx_notify_uid')
                ],
                'url': ''
            }
            url = f'{WX_NOTIFY_BASE_URL}/send/message'
            requests.post(url, json=push_data)
    except Exception as exc:
        print(traceback.format_exc(exc))
    finally:
        after_minute = random.randint(5, 30)
        after_second = random.randint(0, 59)
        job_1 = CronTrigger(day_of_week='0-4', hour=18, minute=after_minute, second=after_second)
        scheduler.add_job(punch_afternoon, job_1, id='afternoon_job')
        signal_af = 1
        print(job_1)


if __name__ == '__main__':
    # 每日开始执行job
    try:
        j1 = CronTrigger(day_of_week='0-4', hour='*', minute='*', second='*/10')
        scheduler.add_job(punch_morning, j1, id='morning_job')

        j2 = CronTrigger(day_of_week='0-4', hour='*', minute='*', second='*/10')
        scheduler.add_job(punch_afternoon, j2, id='afternoon_job')
        scheduler.start()
    except Exception as exc:
        print(exc)
