import random

from client_class import Client
from hashlib import sha256

passwd = sha256(''.encode('utf-8')).hexdigest()

C = Client()
print('insert_secret', C.insert_secret( 'ka7a', passwd, 1, 'qwerty', '21.10.2024', 'TEST!'), '\n----------------')
print('drop_secret'  , C.drop_secret(   'ka7a', passwd, 5)                                 , '\n----------------')
print('grant_all'    , C.grant_all(     'ka7a', passwd, 'TEST_1', 2)                       , '\n----------------')
print('grant_read'   , C.grant_read(    'ka7a', passwd, 'TEST_1', 1)                       , '\n----------------')
print('revoke_read'  , C.revoke_read(   'ka7a', passwd, 'TEST_1', 1)                       , '\n----------------')
print('add_user'     , C.add_user(      'ka7a', passwd, 'TEST_' + str(random.randint(3,100)), '+', 2, 'qtwer', 0)       , '\n----------------')
print('get_secret'   , C.get_secret(    'ka7a', passwd, 2)                                 , '\n----------------')
print('get_my_secrts', C.get_my_secrets('ka7a', passwd)                                    , '\n----------------')
print('get_me_secrts', C.get_my_readable_secrets('ka7a', passwd)                           , '\n----------------')
print('get_contacts' , C.get_contacts(  'ka7a', passwd, 'root')                            , '\n----------------')
print('get_logs'     , C.get_logs(      'ka7a', passwd)                                    , '\n----------------')

