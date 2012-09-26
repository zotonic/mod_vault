%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2012 Marc Worrell
%% @doc Provides model for mod_vault

%% Copyright 2012 Marc Worrell
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% 
%%     http://www.apache.org/licenses/LICENSE-2.0
%% 
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(m_vault).

-export([
	m_find_value/3,
	m_value/2,
	m_to_list/2,


	is_key/2,
	is_key_user/3,
	save_key/6,
	get_public_key/2,
	get_private_key/4,
	delete_key/2,
	delete_private_key/3,
	delete_private_key/2,
	change_private_key_password/5,
	copy_private_key/6,
	init/1
	]).

-include("zotonic.hrl").
-include_lib("public_key/include/public_key.hrl").


m_find_value(list_all_private, #m{value=undefined}, Context) ->
	list_all_private(Context);
m_find_value(is_unlocked, #m{value=undefined} = M, _Context) ->
	M#m{value=is_unlocked};
m_find_value(Name, #m{value=is_unlocked}, Context) ->
	case mod_vault:get_key_session(Name, Context) of
		{ok, _} -> true;
		_ -> false
	end.

m_value(#m{}, _Context) ->
	undefined.

m_to_list(#m{}, _Context) ->
	[].


%% @doc List all private keys of all users
list_all_private(Context) ->
	z_db:assoc("select id, name, user_id from vault where is_private order by name,id", Context).


%% @doc Test if a key is known. The name is case sensitive.
-spec is_key( Name::string()|binary()|atom(), #context{} ) -> boolean().
is_key(Name, Context) ->
	z_convert:to_bool(z_db:q1("select count(*) from vault where name = $1 and not is_private", [Name], Context)).

%% @doc Test if a key is known. The name is case sensitive.
-spec is_key_user( Name::string()|binary()|atom(), UserId::integer(), #context{} ) -> boolean().
is_key_user(Name, UserId, Context) ->
	z_convert:to_bool(z_db:q1("select count(*) from vault where name = $1 and user_id = $2 and is_private", [Name, UserId], Context)).


%% @doc Save the gloval public key and the user's private key, encoded with the password
-spec save_key(#'RSAPrivateKey'{}, #'RSAPublicKey'{}, string()|binary()|atom(), integer(), string()|binary(), #context{}) -> ok | {error, term()}.
save_key(RSAPrivKey, RSAPubKey, Name, UserId, Password, Context) ->
	case is_key(Name, Context) of
		false ->
			% Encode the private key with the password
			PrivEnc = encrypt(Password, RSAPrivKey),
			F = fun(Ctx) ->
					1 = z_db:q("insert into vault (is_private, name, user_id, key)
								 values (false, $1, null, $2)",
								[Name, RSAPubKey],
								Ctx),
					1 = z_db:q("insert into vault (is_private, name, user_id, key)
								 values (true, $1, $2, $3)",
								[Name, UserId, PrivEnc],
								Ctx),
					ok
				end,
			z_db:transaction(F, Context);
		true ->
			{error, key_exists}
	end.



%% @doc Return the named public key.
-spec get_public_key(Name::string()|binary()|atom(), #context{}) -> {ok, #'RSAPublicKey'{}} | {error, not_found}.
get_public_key(Name, Context) ->
	case z_db:q1("select key from vault where name = $1 and not is_private", [Name], Context) of
		undefined -> {error, not_found};
		Key -> {ok, Key}
	end.


%% @doc Return the named private key, encode with password
-spec get_private_key(Name::string()|binary()|atom(), UserId::integer(), Password::string()|binary(), #context{}) -> 
		{ok, #'RSAPrivateKey'{}} | {error, not_found|password}.
get_private_key(Name, UserId, Password, Context) ->
	case z_db:q1("select key 
				  from vault 
				  where name = $1 
				    and user_id = $2 
				    and is_private", 
				 [Name, UserId],
				 Context)
	of
		undefined -> 
			{error, not_found};
		Encoded ->
			Bin = decrypt(Password, Encoded), 
			case catch erlang:binary_to_term(Bin) of
				#'RSAPrivateKey'{} = Key -> {ok, Key};
				_ -> {error, password}
			end
	end.


-spec delete_key(Name::string()|binary()|atom(), #context{}) -> ok.
delete_key(Name, Context) ->
	z_db:q("delete from vault where name = $1", [Name], Context),
	ok.


-spec delete_private_key(Name::string()|binary()|atom()|integer(), UserId::integer(), #context{}) -> ok.
delete_private_key(Name, UserId, Context) ->
	z_db:q("delete from vault where name = $1 and user_id = $2 and is_private",
		   [Name, UserId],
		   Context),
	prune_public_key(Name, Context),
	ok.

-spec delete_private_key(Id::integer(), #context{}) -> ok.
delete_private_key(Id, Context) when is_integer(Id) ->
	Name = z_db:q1("select name from vault where id = $1 and is_private", [Id], Context),
	z_db:q("delete from vault where id = $1 and is_private",
		   [Id],
		   Context),
	prune_public_key(Name, Context),
	ok.

prune_public_key(Name, Context) ->
	case z_db:q1("select count(*) from vault where name = $1 and is_private", [Name], Context) of
		0 -> delete_key(Name, Context);
		_N -> ok
	end.

%% @doc Return the named private key, encode with password
-spec change_private_key_password(Name::string()|binary()|atom(), UserId::integer(),
			PasswordOld::string()|binary(), PasswordNew::string()|binary(),
			#context{}) -> ok | {error, not_found|password}.
change_private_key_password(Name, UserId, PasswordOld, PasswordNew, Context) ->
	case get_private_key(Name, UserId, PasswordOld, Context) of
		{ok, RSAPrivKey} ->
			Encrypted = encrypt(PasswordNew, RSAPrivKey),
			1 = z_db:q("update vault set key = $1 where name = $2 and user_id = $3 and is_private",
				       [Encrypted, Name, UserId],
				       Context),
			ok;
		Error ->
			Error
	end.



%% @doc Copy the private key from one user to another, overwrite existing key.
-spec copy_private_key(Name::string()|binary()|atom(), 
			UserIdFrom::integer(), UserIdTo::integer(),
			PasswordFrom::string()|binary(), PasswordTo::string()|binary(),
			#context{}) -> ok | {error, not_found|password}.
copy_private_key(Name, UserIdFrom, UserIdTo, PasswordFrom, PasswordTo, Context) ->
	case get_private_key(Name, UserIdFrom, PasswordFrom, Context) of
		{ok, RSAPrivKey} ->
			Encrypted = encrypt(PasswordTo, RSAPrivKey),
			case is_key_user(Name, UserIdTo, Context) of
				true ->
					1 = z_db:q("update vault set key = $1 where name = $2 and user_id = $3 and is_private",
						       [Encrypted, Name, UserIdTo],
						       Context);
				false ->
					1 = z_db:q("insert into vault (is_private, name, user_id, key)
								 values (true, $1, $2, $3)",
								[Name, UserIdTo, Encrypted],
								Context)
			end,
			ok;
		Error ->
			Error
	end.
	


encrypt(Password, Term) ->
	PW = z_convert:to_binary(Password),
	IVec = crypto:rand_bytes(8),
	Bin = erlang:term_to_binary(Term), 
	Enc = crypto:blowfish_cfb64_encrypt(PW, IVec, Bin),
	{blowfish_cfb64_encrypt, IVec, Enc}.

decrypt(Password, {blowfish_cfb64_encrypt, IVec, Enc}) ->
	PW = z_convert:to_binary(Password),
	crypto:blowfish_cfb64_decrypt(PW, IVec, Enc).


%% @doc Install the tables needed for the vault key administration.
-spec init(#context{}) -> ok.
init(Context) ->
	case z_db:table_exists(vault, Context) of
		false ->
			[] = z_db:q("
					create table vault (
						id serial not null,
						is_private boolean not null,
						name character varying(64) not null,
						user_id int,
						key bytea not null,

						primary key (id),
						constraint fk_vault_user_id foreign key (user_id) references rsc(id)
							on update cascade on delete cascade
				    )", 
				    Context),
			[] = z_db:q("create index vault_user_id_name_key on vault(user_id,name)", Context),
			[] = z_db:q("create index vault_name_key on vault(name)", Context),
			z_db:flush(Context),
			ok;
		true ->
			ok
	end.

