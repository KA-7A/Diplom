from client_class import Client
from time import sleep

C = Client()
print(C.insert_secret('ka7a', '-', 1, 'qwerty', '21.10.2024', 'TEST!'))
print(C.drop_secret('ka7a', '-', 5))
print(C.grant_all('ka7a', '-', 'unknown', 6))
print(C.grant_read('ka7a', '-', 'TEST_1', 7))
print(C.revoke_read('ka7a', '-', 'TEST_1', 7))
print(C.add_user('ka7a', '-', 'TEST_1', '+', 2, 'qwer', 0))
print(C.get_secret('ka7a', '-', 8))
print(C.get_my_secrets('ka7a', '-'))
print(C.get_my_readable_secrets('ka7a', '-'))
print(C.get_contacts('ka7a', '-', 'root'))
print(C.get_logs('ka7a', '-'))

