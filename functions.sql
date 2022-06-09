-- Процедуры
-- -- m_log (user_id, user_action, return_code)
drop procedure if exists m_log;
delimiter |
create procedure m_log(in i_user_id int, in i_user_action int, in i_return_code int)
begin
    insert into LOGS
    (USER_ID,      L_TIME,     USER_ACTION,      RETURN_CODE) values
    (i_user_id,    SYSDATE(),  i_user_action,    i_return_code);
end |
delimiter ;

-- Функции
-- -- Служебные
-- -- -- get_user_id (user_name)
drop function if exists get_user_id;
DELIMITER &&
create function get_user_id(i_user_name varchar(100))
returns MEDIUMINT
deterministic
begin
    declare tmp_id int;
    declare tmp_count int;
    set tmp_id = 2;
    select  count(*) into @tmp_count from USERS
        where NAME = i_user_name;
    if (@tmp_count != 1) then
        return 2;
    end if;
    select  id into @tmp_id from USERS
        where NAME = i_user_name;
    return @tmp_id;

end&&
delimiter ;
select get_user_id('root');
select get_user_id('unknown');
select get_user_id('123');

-- -- -- get_salt (user_name)
drop function if exists get_salt;
DELIMITER &&
create function get_salt(i_user_name varchar(100))
returns MEDIUMINT
deterministic
begin
    declare tmp_num int;
    set tmp_num = -1;
    select ID into @tmp_num from USERS
        where NAME = i_user_name;
    if tmp_num < 0 then
        set tmp_num = 2;
    end if;
    return @tmp_num;

end&&
delimiter ;

-- -- -- check_access (user_name, user_hash)
drop function if exists check_access;
DELIMITER &&&
create function check_access(i_user_name varchar(100), i_user_hash varchar(100))
returns MEDIUMINT
deterministic
begin
    declare tmp_count int;
    select count(*) into @tmp_count from USERS
        where NAME = i_user_name and HASH = i_user_hash;

    if (@tmp_count = 1) then
        call m_log(get_user_id(i_user_name), 1, 1);
        return 1;
    else
        call m_log(get_user_id(i_user_name), 1, -1);
        return -1;
    end if;
end&&&
delimiter ;
select check_access('root', '_');
select check_access('root', '__');
select check_access('root', '_');

-- -- -- check_privileges (user_name)
-- -- -- Используется только после check_access!
drop function if exists check_privileges;
delimiter  &&&
create function check_privileges(i_user_name varchar(100))
returns int
deterministic
begin
    declare res int;
    set res = 0;
    select PRIVILEGED into @res from USERS
        where NAME = i_user_name;
    return @res;
end&&&
delimiter ;
select check_privileges('root');
select check_privileges('unknown');


-- -- Пользовательские
-- -- -- get_secret (user_name, user_hash, secret_num)
drop function if exists get_secret;
delimiter &&&
create function get_secret(i_user_name varchar(100), i_user_hash varchar(100), i_secret_num int)
returns text
deterministic
begin
    declare tmp_count int;
    declare responce text;
    if (check_access(i_user_name, i_user_hash) = -1) then
        return 'Access denied!';
    end if;
    if (check_privileges(i_user_name) = 1) then
        select count(*) into @tmp_count from READABLE
            where   SECRET_ID = i_secret_num;
    else
        select count(*) into @tmp_count from READABLE
            where   USER_ID = get_user_id(i_user_name) and
                    SECRET_ID = i_secret_num;
    end if;
    if (@tmp_count = 0) then
        call m_log(get_user_id(i_user_name), 1, -3);
        return 'You do not has permissions to this secret or secret was now found';
    else
        call m_log(get_user_id(i_user_name), 1, 3);
        select secret into @responce from SECRETS where ID = i_secret_num;
        return @responce;
    end if;

end &&&
delimiter ;
select get_secret('root', '_', 1);
select get_secret('root', '__', 1);
select get_secret('unknown', '_', 2);
select get_secret('root', '_', 3);
select get_secret('unknown', '_', 3);

-- -- -- get_my_secrets (user_name, user_hash)

-- -- -- get_my_readable_secrets (user_name, user_hash)

-- -- -- get_contacts (user_1_name, user_1_hash, user_2_name)

-- -- -- get_logs (user_name, user_hash)

-- -- -- -- -- -- -- -- -- -- -- -- --
-- -- -- insert_secret (user_name, user_hash, secret_type, secret_secret, secret_valid_to, secret_description)

-- -- -- drop_secret( user_name, user_hash, secret_num)

-- -- -- update_secret (user_name, user_hash, secret_num, secret_type, secret_secret, secret_valid_to, secret_description)

-- -- -- grant_all (user_1_name, user_1_hash, user_2_name, secret_num)

-- -- -- grant_read (user_1_name, user_1_hash, user_2_name, secret_num)

-- -- -- revoke_read (user_1_name, user_1_hash, user_2_name, secret_num)


-- -- -- add_contact (user_1_name, user_1_hash, user_contact)

-- -- -- add_user (user_1_name, user_1_hash, user_2_name, user_2_hash, user_2_type, user_2_salt, user_2_privileged)



