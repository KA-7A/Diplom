from server_class import Server_to_SQL

S = Server_to_SQL()
print(S.get_secret('root', '_', 2))
print(S.get_secret('root', '__', 2))
print(S.get_secret('unknown', '_', 2))
print(S.get_my_secrets('root', '_'))
print(S.get_my_readable_secrets('root', '_'))
print(S.get_logs('ka_7a', '-'))

print(S.get_contacts('ka7a', '-', 'ka7a'))
print(S.add_contact('ka7a', '-', '+7-977-770-28-38'))
print(S.get_contacts('ka7a', '-', 'ka7a'))

print(S.insert_secret('ka7a', '-', '1', 'asdfzxcv', '12.10.2024', 'Test'))
print(S.drop_secret('ka7a', '-', 15))

print(S.grant_all('ka7a', '-', 'root', 10))
print(S.grant_all('unknown', '_', 'root', 10))
print(S.grant_read('ka7a', '-', 'root', 10))
print(S.revoke_read('ka7a', '-', 'ka7a', 10))

print(S.add_user('ka7a', '-', 'tmp', '+', 1, 'no_salt', 0))