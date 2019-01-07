import base64
import socket

from api.spider.xhs import xiaohongshu
from api.spider.xhs.message_pb2 import ChatModel, Msg, AuthDevice, AuthMsg, \
    Auth, SessionAuthMsg, AuthSession
from api.utils.common import hash_md5_bytes, get_random_string, get_random_int
from toolkit.time_utils import get_timestamp_mills


class Chat():
    s = socket.socket()
    host = 'apppush.xiaohongshu.com'
    port = 5333
    s.settimeout(3)
    s.connect((host, port))

    def encrypt_data(self, data):
        mask = bytearray([6, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0])
        length = len(data)
        b = length & 255 & 0xff
        b2 = (length >> 8) & 255 & 0xff
        b3 = (length >> 16) & 255 & 0xff
        a = hash_md5_bytes(data)
        mask[2] = 1
        mask[5] = b3
        mask[6] = b2
        mask[7] = b
        mask[9] = a[13] & 0xff  # int to byte
        mask[10] = a[14] & 0xff
        mask[11] = a[15] & 0xff
        return mask

    def decrypt_data(self, data):
        header = data[:12]
        e = ((header[7] & 255) + ((header[6] & 255) << 8)) + (
            (header[5] & 255) << 16)
        ret = data[12:(12 + e)]
        return ret

    def ping(self):
        payload = bytearray([6, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0])
        resp = self.send_payload(payload)
        print(resp)

    def auth(self):
        ad = AuthDevice()
        ad.device_id = xiaohongshu.device_id
        ad.auth_type = 'phone'
        ad.platform = 'Android'
        ad.model = xiaohongshu.model
        ad.version = '5.35.0'
        ad.android_sdk = '6.0.1'
        auth_msg = AuthMsg()
        auth_msg.sender = xiaohongshu.user_id
        auth_msg.session_id = xiaohongshu.session_id
        auth_msg.device_id = xiaohongshu.device_id
        auth_msg.defaule_red = 'red'
        auth_msg.auth_device.MergeFrom(ad)
        auth_payload = Auth()
        auth_payload.default1 = 1
        auth_payload.auth_msg.MergeFrom(auth_msg)
        payload = auth_payload.SerializeToString()
        print(base64.urlsafe_b64encode(payload))
        payload = self.encrypt_data(payload) + payload
        resp = self.send_payload(payload)
        ##todo 检查payload正确
        print(resp)

    def sessionAuth(self):
        ad = AuthDevice()
        ad.device_id = xiaohongshu.device_id
        ad.auth_type = 'phone'
        ad.platform = 'Android'
        ad.model = xiaohongshu.model
        ad.version = '5.35.0'
        ad.android_sdk = '6.0.1'
        auth_msg = SessionAuthMsg()
        auth_msg.sender_timettamp = f'{xiaohongshu.user_id}-{get_timestamp_mills()}'
        auth_msg.sender = xiaohongshu.user_id
        auth_msg.session_id = xiaohongshu.session_id
        auth_msg.auth_type = 'SessionAuth'
        auth_msg.default_red = 'red'
        auth_msg.auth_device.MergeFrom(ad)
        auth_payload = AuthSession()
        auth_payload.default1 = 1
        auth_payload.auth_msg.MergeFrom(auth_msg)
        payload = auth_payload.SerializeToString()
        print(base64.urlsafe_b64encode(payload))
        payload = self.encrypt_data(payload) + payload
        print(base64.b64encode(payload))
        resp = self.send_payload(payload)
        resp = self.decrypt_data(resp)
        print('result:' + base64.b64encode(resp).decode())
        print(resp)
        return resp

    def send_msg(self, textmsg, receiver, nickname):
        msg = Msg()
        msg.mid = get_random_int(42)
        msg.timestamp = get_timestamp_mills()
        msg.chatToken = f'{xiaohongshu.user_id}@red@phone@1'
        msg.sender = xiaohongshu.user_id
        msg.receiver = receiver
        msg.content = textmsg
        msg.ii = 1
        msg.nickname = nickname
        cm = ChatModel()
        cm.a = 1
        cm.msg.MergeFrom(msg)
        payload = cm.SerializeToString()
        payload = self.encrypt_data(payload) + payload
        resp = self.send_payload(payload)

        # payload = base64.b64decode('BgAAAAUAAAAAAAAA')
        # s.send(payload)


        print(resp)
        print(base64.b64encode(resp))
        if 'ok' in str(resp):
            print(f'发送成功：{receiver}')
            return True
        else:
            print(f'发送失败：{receiver}')
            return False

    def send_img(self, content, receiver, nickname):
        msg = Msg()
        msg.mid = get_random_int(42)
        msg.timestamp = get_timestamp_mills()
        msg.chatToken = f'{xiaohongshu.user_id}@red@phone@1'
        msg.sender = xiaohongshu.user_id
        msg.receiver = receiver
        msg.content = content
        msg.ii = 2
        msg.nickname = nickname
        cm = ChatModel()
        cm.a = 1
        cm.msg.MergeFrom(msg)
        payload = cm.SerializeToString()
        payload = self.encrypt_data(payload) + payload
        print(base64.b64encode(payload))
        resp = self.send_payload(payload)

        # payload = base64.b64decode('BgAAAAUAAAAAAAAA')
        # s.send(payload)
        print(resp)
        print(f'send image result:{base64.b64encode(resp)}')

        if 'Antispam' in str(resp):
            print('消息被拦截')
            return False
        return True

    def send_payload(self, payload):
        try:
            self.s.send(payload)
            return self.s.recv(10240)
        except socket.timeout as to:
            return b''
