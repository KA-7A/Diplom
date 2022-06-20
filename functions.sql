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
drop function if exists get_error_description;
DELIMITER &&
create function get_error_description(i_error_id int)
returns varchar(50)
deterministic
begin
    declare resp varchar(50);
    select TYPE into resp from RETURN_CODES where ID = i_error_id;
    return resp;
end&&
delimiter ;


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

-- -- -- get_salt (user_name)
drop function if exists get_salt;
DELIMITER &&
create function get_salt(i_user_name varchar(100))
returns varchar(10)
deterministic
begin
    declare tmp_salt varchar(10);
    set tmp_salt = "";
    select SALT into tmp_salt from USERS
        where ID = get_user_id(i_user_name);
    return tmp_salt;
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
        return 0;
    end if;
end&&&
delimiter ;

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
    if (check_access(i_user_name, i_user_hash) = 0) then
        return 'Error[-1]: Access denied!';
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
        return 'Error[-3]: You do not has permissions to this secret or secret was now found';
    else
        call m_log(get_user_id(i_user_name), 1, 3);
        select secret into @responce from SECRETS where ID = i_secret_num;
        return @responce;
    end if;

end &&&
delimiter ;

-- -- -- get_my_secrets (user_name, user_hash)
drop function if exists get_my_secrets;
delimiter &&&
create function get_my_secrets(i_user_name varchar(100), i_user_hash varchar(100))
returns text
deterministic
begin
    declare response text default "(";
    declare tmp_string varchar(10);
    declare tmp_id int;
    declare done integer default 0;
    declare cur cursor for select SECRET_ID from OWNERSHIP where USER_ID = get_user_id(i_user_name);
    declare continue handler for sqlstate '02000' set done=1;

    if (check_access(i_user_name, i_user_hash) = 0) then
        return "Error[-1]: Access denied";
    end if;
    open cur;
    m_loop: while (done = 0) do
        set tmp_id = 0;
        set tmp_string = "";
        FETCH cur into tmp_id;
        if (tmp_id = 0) then
            leave m_loop;
        end if;
        set tmp_string = CONVERT(tmp_id, char);
        if (LENGTH(response) = 1) then
            set response = CONCAT(response, tmp_string);
        else
            set response = CONCAT(response, ", ", tmp_string);
        end if;
    end while;
    set response = CONCAT(response, ")");

    close cur;
    call m_log(get_user_id(i_user_name), 1, 4);
    return response;
end&&&
delimiter ;

-- -- -- get_my_readable_secrets (user_name, user_hash)
drop function if exists get_my_readable_secrets;
delimiter &&&
create function get_my_readable_secrets(i_user_name varchar(100), i_user_hash varchar(100))
returns text
deterministic
begin
    declare response text default "(";

    declare tmp_string      varchar(10);
    declare tmp_cur_secret_id   int;
    declare tmp_cur_user_id     int;
    declare tmp_user_prv        int     default 0;
    declare tmp_user_id         int     default 0;

    declare done integer default 0;
    declare cur cursor for select SECRET_ID, USER_ID from READABLE;
    declare continue handler for sqlstate '02000' set done=1;

    if (check_access(i_user_name, i_user_hash) = 0) then
        return "Error[-1]: Access denied";
    end if;
    set tmp_user_prv    = check_privileges(i_user_name);
    set tmp_user_id     = get_user_id(i_user_name);

    open cur;
    m_loop: while (done = 0) do
        set tmp_cur_secret_id = 0;
        set tmp_string = "";
        FETCH cur into tmp_cur_secret_id, tmp_cur_user_id;
        if (tmp_cur_secret_id = 0) then
            leave m_loop;
        end if;
        if (tmp_user_prv = 1 or tmp_user_id = tmp_cur_user_id) then
            set tmp_string = CONVERT(tmp_cur_secret_id, char);
            if (LENGTH(response) = 1) then
                set response = CONCAT(response, tmp_string);
            else
                set response = CONCAT(response, ", ", tmp_string);
            end if;
        end if;
    end while;
    set response = CONCAT(response, ")");

    close cur;

    call m_log(get_user_id(i_user_name), 1, 5);
    return response;
end&&&
delimiter ;

-- -- -- get_users(user_name, user_hash)
drop function if exists get_users;
delimiter &&&
create function get_users(i_user_name varchar(100), i_user_hash varchar(100))
returns text
deterministic
begin
    declare response text default "(";

    declare tmp_string      varchar(50);

    declare done integer default 0;
    declare cur cursor for select NAME from USERS where NAME!='unknown';
    declare continue handler for sqlstate '02000' set done=1;

    if (check_access(i_user_name, i_user_hash) = 0) then
        return "Error[-1]: Access denied";
    end if;


    open cur;
    m_loop: while (done = 0) do
        set tmp_string = "";
        FETCH cur into tmp_string;
        if (tmp_string = "") then
            leave m_loop;
        end if;
        if (LENGTH(response) = 1) then
            set response = CONCAT(response, "'",tmp_string,"'");
        else
            set response = CONCAT(response, ",'",tmp_string,"'");
        end if;
    end while;
    set response = CONCAT(response, ")");

    close cur;
    call m_log(get_user_id(i_user_name), 1, 17);
    return response;
end&&&
delimiter ;

-- -- -- get_contacts (user_1_name, user_1_hash, user_2_name)
drop function if exists get_contacts;
delimiter &&&
create function get_contacts(i_user_1_name varchar(100), i_user_1_hash varchar(100), i_user_2_name varchar(100))
returns text
deterministic
begin
    declare response text default "(";

    declare tmp_string      varchar(50);
    declare tmp_user_1_id   int default 0;
    declare tmp_user_2_id   int default 0;

    declare done integer default 0;
    declare cur cursor for select CONTACT from CONTACTS where ID = get_user_id(i_user_2_name);
    declare continue handler for sqlstate '02000' set done=1;

    if (check_access(i_user_1_name, i_user_1_hash) = 0) then
        return "Error[-1]: Access denied";
    end if;
    set tmp_user_1_id     = get_user_id(i_user_1_name);
    set tmp_user_2_id     = get_user_id(i_user_2_name);


    open cur;
    m_loop: while (done = 0) do
        set tmp_string = "";
        FETCH cur into tmp_string;
        if (tmp_string = "") then
            leave m_loop;
        end if;
        if (LENGTH(response) = 1) then
            set response = CONCAT(response, "'",tmp_string,"'");
        else
            set response = CONCAT(response, ",'",tmp_string,"'");
        end if;
    end while;
    set response = CONCAT(response, ")");

    close cur;
    call m_log(get_user_id(i_user_1_name), 1, 5);
    return response;
end&&&
delimiter ;

-- -- -- get_logs (user_name, user_hash)
-- select L.ID, L.L_TIME, U.NAME, AT.TYPE, RC.TYPE
--    from  LOGS as L,  USERS as U, RETURN_CODES as RC, ACTION_TYPE AS AT
--    where L.USER_ID = U.ID and L.RETURN_CODE = RC.ID and L.USER_ACTION = AT.ID
--    order by L.ID DESC
--    limit 10;

drop function if exists get_logs;
delimiter &&&
create function get_logs(i_user_name varchar(100), i_user_hash varchar(100))
returns text
deterministic
begin
    declare response text default "(";
    declare tmp_user_prv int default 0;
    declare tmp_id int;
    declare tmp_time datetime;
    declare tmp_name varchar(100);
    declare tmp_type varchar(1);
    declare tmp_return varchar(100);

    declare done integer default 0;
    declare cur cursor for select L.ID, L.L_TIME, U.NAME, AT.TYPE, RC.TYPE from LOGS as L, USERS as U, RETURN_CODES as RC, ACTION_TYPE AS AT
    where L.USER_ID = U.ID and L.RETURN_CODE = RC.ID and L.USER_ACTION = AT.ID
    order by L.ID DESC
    limit 10;
    declare continue handler for sqlstate '02000' set done=1;

    if (check_access(i_user_name, i_user_hash) = 0) then
        return "Error[-1]: Access denied";
    end if;
    if (check_privileges(i_user_name) = 0) then
        call m_log(get_user_id(i_user_name), 1, -7);
        return "Error[-7]: Access denied";
    end if;

    open cur;
    m_loop: while (done = 0) do
        set tmp_return = "";
        FETCH cur into tmp_id, tmp_time, tmp_name, tmp_type, tmp_return;
        if (tmp_return = "") then
            leave m_loop;
        end if;
        if (LENGTH(response) = 1) then
            set response = CONCAT(response, "(" ,   CONVERT(tmp_id, char)   ,",'",
                                                    CONVERT(tmp_time, char) ,"','",
                                                    tmp_name                , "','",
                                                    tmp_type                , "','",
                                                    tmp_return,"')");
        else
            set response = CONCAT(response, ",(" ,  CONVERT(tmp_id, char)   ,",'",
                                                    CONVERT(tmp_time, char) ,"','",
                                                    tmp_name                , "','",
                                                    tmp_type                , "','",
                                                    tmp_return,"')");
        end if;
    end while;

    set response = CONCAT(response, ")");
    call m_log(get_user_id(i_user_name), 1, 7);
    return response;
end&&&
delimiter ;

-- -- -- -- -- -- -- -- -- -- -- -- --
-- -- -- insert_secret (user_name, user_hash,  secret_type, secret_secret, secret_valid_to, secret_description, return_code)
drop procedure if exists insert_secret;
delimiter |
create procedure insert_secret( in i_user_name          varchar(100),
                                in i_user_hash          varchar(100),
                                in i_secret_type        int,
                                in i_secret_secret      text,
                                in i_secret_valid_to    text,
                                in i_secret_description text,
                                out return_code         int)
l:begin
    declare tmp_id  int;
    declare tmp     int default 0;
    declare date_to date;
    if (check_access(i_user_name, i_user_hash) = 0) then
        set return_code = -1;
        leave l;
    end if;
    select count(*) into @tmp from SECRET_TYPE where ID = i_secret_type;
    if (@tmp != 1) then
        set return_code = -9;
        call m_log(get_user_id(i_user_name), 3, -9);
        leave l;
    end if;
    if (LENGTH(i_secret_valid_to) = 0) then
        set i_secret_valid_to = null;
    else
        set date_to = STR_TO_DATE(i_secret_valid_to, '%d.%m.%Y');
    end if;
    if (date_to <= SYSDATE() and date_to is not null) then
        set return_code = -8;
        call m_log(get_user_id(i_user_name), 3, -8);
        leave l;
    end if;
    select count(*) into return_code from SECRETS;
    if (return_code = 0) then
        set return_code = 1;
    else
        select max(ID)+1 into return_code from SECRETS;
    end if;

    insert into SECRETS (ID,      TYPE,            VALID_TO, SECRET,          DESCRIPTION) values
                        (return_code, i_secret_type,   date_to , i_secret_secret, i_secret_description);
    commit;
    insert into OWNERSHIP   (SECRET_ID, USER_ID) values
                            (return_code,   get_user_id(i_user_name));

    call m_log(get_user_id(i_user_name), 3, 8);
    call m_log(get_user_id(i_user_name), 3, 9);

end|
delimiter ;
-- -- -- update_secret(user_name, user_hash, secret_id,  secret_type, secret_secret, secret_valid_to, secret_description, return_code)
drop procedure if exists update_secret;
delimiter |
create procedure update_secret( in i_user_name          varchar(100),
                                in i_user_hash          varchar(100),
                                in i_secret_id          int,
                                in i_secret_type        int,
                                in i_secret_secret      text,
                                in i_secret_valid_to    text,
                                in i_secret_description text,
                                out return_code         int)
l:begin
    declare tmp_id  int;
    declare tmp     int default 0;
    declare date_to date;
    if (check_access(i_user_name, i_user_hash) = 0) then
        set return_code = -1;
        leave l;
    end if;
    select count(*) into @tmp from OWNERSHIP where USER_ID = get_user_id(i_user_name) and SECRET_ID = i_secret_id;
    if (check_privileges(i_user_name) = 0 and  @tmp = 0) then
        set return_code = -11;
        call m_log(get_user_id(i_user_name), 2, -11 );
        leave l;
    end if;
    select count(*) into @tmp from SECRET_TYPE where ID = i_secret_type;
    if (@tmp != 1) then
        set return_code = -9;
        call m_log(get_user_id(i_user_name), 2, -9);
        leave l;
    end if;
    if (LENGTH(i_secret_valid_to) = 0) then
        set i_secret_valid_to = null;
    else
        set date_to = STR_TO_DATE(i_secret_valid_to, '%d.%m.%Y');
    end if;
    if (date_to <= SYSDATE() and date_to is not null) then
        set return_code = -8;
        call m_log(get_user_id(i_user_name), 2, -8);
        leave l;
    end if;
    select count(*) into return_code from SECRETS where ID = i_secret_id;
    if (return_code = 0) then
        set return_code = -11;
        call m_log(get_user_id(i_user_name), 2, -11);
        leave l;
    end if;
    update SECRETS set TYPE=i_secret_type, VALID_TO = date_to, SECRET = i_secret_secret, DESCRIPTION = i_secret_description;
    commit;
    set return_code = 18;
    call m_log(get_user_id(i_user_name), 2, 18);
end|
delimiter ;

-- -- -- drop_secret( user_name, user_hash, secret_num, return_code)
drop procedure if exists drop_secret;
delimiter |
create procedure drop_secret(in i_user_name varchar(100), in i_user_hash varchar(100), in i_secret_num int, out o_return_code int)
l:begin
    declare tmp int;

    if (check_access(i_user_name, i_user_hash) = 0) then
        set o_return_code = -1;
        leave l;
    end if;
    if (check_privileges(i_user_name) != 1) then
        select count(*) into @tmp from OWNERSHIP where USER_ID = get_user_id(i_user_name) and SECRET_ID = i_secret_num;
        if (@tmp = 1) then
            delete from OWNERSHIP where SECRET_ID   = i_secret_num;
            delete from READABLE  where SECRET_ID   = i_secret_num;
            delete from SECRETS   where ID          = i_secret_num;
            set o_return_code = 10;
            call m_log(get_user_id(i_user_name), 4, 10);
            leave l;
        else
            set o_return_code = -10;
            call m_log(get_user_id(i_user_name), 4, -10);
            leave l;
        end if;
    else
        select count(*) into @tmp from OWNERSHIP where SECRET_ID = i_secret_num;
        if (@tmp = 1) then
            delete from OWNERSHIP where SECRET_ID   = i_secret_num;
            delete from READABLE  where SECRET_ID   = i_secret_num;
            delete from SECRETS   where ID          = i_secret_num;
            set o_return_code = 10;
            call m_log(get_user_id(i_user_name), 4, 10);
        else
            set o_return_code = -17;
            call m_log(get_user_id(i_user_name), 4, -17);
        end if;
        leave l;
    end if;
end|
delimiter ;


-- -- -- grant_all (user_1_name, user_1_hash, user_2_name, secret_num, return_code)
drop procedure if exists grant_all;
delimiter |
create procedure grant_all( in i_user_1_name varchar(100),
                            in i_user_1_hash varchar(100),
                            in i_user_2_name varchar(100),
                            in i_secret_num   int,
                            out o_return_code int)
l:begin
    declare tmp int;

    if (check_access(i_user_1_name, i_user_1_hash) = 0) then
        set o_return_code = -1;
        leave l;
    end if;

    select count(*) into @tmp from OWNERSHIP
        where   USER_ID = get_user_id(i_user_1_name) and
                SECRET_ID = i_secret_num;
    if (@tmp = 1 or check_privileges(i_user_1_name) = 1) then
        if (get_user_id(i_user_2_name) = 2) then
            set o_return_code = -16;
            call m_log(get_user_id(i_user_1_name), 2, -16);
            leave l;
        end if;
        update OWNERSHIP set USER_ID = get_user_id(i_user_2_name) where SECRET_ID = i_secret_num;
        insert into READABLE (USER_ID, SECRET_ID) values (get_user_id(i_user_2_name), i_secret_num);
        set o_return_code = 11;
        call m_log(get_user_id(i_user_1_name), 2, 11);
        leave l;
    else
        set o_return_code = -11;
        call m_log(get_user_id(i_user_1_name), 2, -11);
        leave l;
    end if;

end|
delimiter ;

-- -- -- grant_read (user_1_name, user_1_hash, user_2_name, secret_num, return_code)
drop procedure if exists grant_read;
delimiter |
create procedure grant_read( in i_user_1_name varchar(100),
                            in i_user_1_hash varchar(100),
                            in i_user_2_name varchar(100),
                            in i_secret_num   int,
                            out o_return_code int)
l:begin
    declare tmp int;

    if (check_access(i_user_1_name, i_user_1_hash) = 0) then
        set o_return_code = -1;
        leave l;
    end if;

    select count(*) into @tmp from READABLE
        where   USER_ID = get_user_id(i_user_1_name) and
                SECRET_ID = i_secret_num;
    if (@tmp = 1 or check_privileges(i_user_1_name) = 1) then
        insert into READABLE (USER_ID, SECRET_ID) values (get_user_id(i_user_2_name), i_secret_num);
        set o_return_code = 12;
        call m_log(get_user_id(i_user_1_name), 2, 12);
        leave l;
    else
        set o_return_code = -12;
        call m_log(get_user_id(i_user_1_name), 2, -12);
        leave l;
    end if;

end|
delimiter ;

-- -- -- revoke_read (user_1_name, user_1_hash, user_2_name, secret_num, return_code)
drop procedure if exists revoke_read;
delimiter |
create procedure revoke_read( in i_user_1_name varchar(100),
                            in i_user_1_hash varchar(100),
                            in i_user_2_name varchar(100),
                            in i_secret_num   int,
                            out o_return_code int)
l:begin
    declare tmp int;

    if (check_access(i_user_1_name, i_user_1_hash) = 0) then
        set o_return_code = -1;
        leave l;
    end if;
    if (i_user_1_name = i_user_2_name) then
        set o_return_code = -13;
    end if;
    select count(*) into @tmp from OWNERSHIP
        where   USER_ID = get_user_id(i_user_2_name) and
                SECRET_ID = i_secret_num;
    if (@tmp = 1) then
        set o_return_code = -14;
        call m_log(get_user_id(i_user_1_name), 4, -14);
        leave l;
    end if;
    select count(*) into @tmp from OWNERSHIP
        where   USER_ID = get_user_id(i_user_1_name) and
                SECRET_ID = i_secret_num;
    if (@tmp = 1 or check_privileges(i_user_1_name) = 1) then
        delete from READABLE where  USER_ID = get_user_id(i_user_2_name) and
                                    SECRET_ID = i_secret_num;
        set o_return_code = 13;
        call m_log(get_user_id(i_user_1_name), 4, 13);
        leave l;
    else
        set o_return_code = -10;
        call m_log(get_user_id(i_user_1_name), 4, -10);
        leave l;
    end if;
end|
delimiter ;

-- -- -- add_contact (user_name, user_hash, user_contact, return_code)
drop procedure if exists add_contact;
delimiter |
create procedure add_contact( in i_user_name varchar(100),
                                in i_user_hash varchar(100),
                                in i_user_contact varchar(100),
                                out o_return_code int)
l:begin
    declare tmp int;

    if (check_access(i_user_name, i_user_hash) = 0) then
        set o_return_code = -1;
        leave l;
    end if;
    select count(*) into @tmp from CONTACTS
        where ID = get_user_id(i_user_name) and CONTACT = i_user_contact;
    if (@tmp != 0) then
        set o_return_code = -15;
        call m_log(get_user_id(i_user_name), 3, -15);
        leave l;
    end if;
    insert into CONTACTS (ID, CONTACT) values (get_user_id(i_user_name), i_user_contact);
    set o_return_code = 15;
    call m_log(get_user_id(i_user_name), 3, 15);
end|
delimiter ;

-- -- -- add_user (user_1_name, user_1_hash, user_2_name, user_2_hash, user_2_type, user_2_salt, user_2_privileged, return_code)
drop procedure if exists add_user;
delimiter |
create procedure add_user( in i_user_1_name  varchar(100),
                                in i_user_1_hash  varchar(64),
                                in i_user_2_name  varchar(100),
                                in i_user_2_hash  varchar(64),
                                in i_user_2_type  int,
                                in i_user_2_salt  varchar(10),
                                in i_user_2_privileged tinyint(1),
                                out o_return_code         int)
l:begin
    declare tmp_id  int;
    declare tmp     int default 0;
    if (check_access(i_user_1_name, i_user_1_hash) = 0 or check_privileges(i_user_1_name) = 0 ) then
        set o_return_code = -1;
        leave l;
    end if;
    select count(*) into @tmp from USERS where NAME = i_user_2_name;
    if (@tmp != 0) then
        set o_return_code = -15;
        call m_log(get_user_id(i_user_1_name), 3, -15);
        leave l;
    end if;
    insert into USERS (NAME, HASH, SALT, PRIVILEGED, TYPE) values
                      (i_user_2_name, i_user_2_hash, i_user_2_salt, i_user_2_privileged, i_user_2_type);
    set o_return_code = 16;
    call m_log(get_user_id(i_user_1_name), 3, 16);
end |
delimiter ;

-- -- -- update_password(user_name, user_hash, new_user_hash)
drop procedure if exists update_password;
delimiter |
create procedure update_password( in i_user_name  varchar(100),
                                  in i_user_hash  varchar(64),
                                  in i_new_user_hash varchar(64),
                                  out o_return_code         int)
l:begin
    if (check_access(i_user_name, i_user_hash) = 0) then
        set o_return_code = -1;
        leave l;
    end if;
    update USERS set HASH = i_new_user_hash where NAME = i_user_name;
    set o_return_code = 19;
    call m_log(get_user_id(i_user_name), 2, 19);
    leave l;
end|
delimiter ;

