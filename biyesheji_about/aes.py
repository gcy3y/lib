#        from Crypto import Random
#      >>>
   
#       >>> key = b'Sixteen byte key'
#       >>> iv = Random.new().read(AES.block_size)
#
#       >>> cipher = AES.new(key, AES.MODE_CFB, iv)
#       >>> msg = iv + cipher.encrypt(b'Attack at dawn')
from Crypto import Random
from Crypto.Cipher import AES
key = '1234567812345678'
iv = Random.new().read(AES.block_size)
cipher = AES.new(key, AES.MODE_CFB, iv)
import base64

msg = base64.b64encode(cipher.encrypt('helloworld'))
print(msg)
msg_decode = cipher.decrypt(base64.b64decode(msg))
print(msg_decode)
