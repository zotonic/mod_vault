%% @doc Provides encryption of values.

-module(mod_vault).

-mod_title("Secure Vault").
-mod_description("Implements a secure vault for encryption of data.").
-mod_schema(1).

-export([
	observe_vault_decode/2,
	observe_vault_encode/2,
	observe_vault_is_unlocked/2,
	event/2,
	manage_schema/2,

	generate_key/4,
	unlock_key_session/3,
	lock_key_session/2,
	get_key_session/2,
	decode_term_session/2,
	encode_term/3,
	decode_term/2,
	decode_term/4,
	get_encode_vault/1
	]).


-include("zotonic.hrl").
-include_lib("public_key/include/public_key.hrl").


-define(RSA_KEY_BITS, 2048).

-record(vault, {
		name :: binary(),
		header :: binary(),
		data :: binary(),
		timestamp :: {integer(), integer(), integer()}
	}).


observe_vault_decode({vault_decode, Data, UserId, Password}, Context) ->
	decode_term(Data, UserId, Password, Context);
observe_vault_decode({vault_decode, Data}, Context) ->
	decode_term_session(Data, Context).

observe_vault_encode({vault_encode, Name, Data}, Context) ->
	encode_term(Name, Data, Context).

observe_vault_is_unlocked({vault_is_unlocked, Name}, Context) ->
	case get_key_session(Name, Context) of
		{ok, _} -> true;
		_ -> false
	end.



event(#submit{message={vault_unlock, Args}, form=FormId}, Context) ->
	Password = z_context:get_q("password", Context),
	Name = proplists:get_value(name, Args),
	case unlock_key_session(Name, Password, Context) of
		ok -> 
			z_render:wire({reload, []}, Context);
		_ ->
			z_render:wire({add_class, [
								{selector, "#"++FormId++" .control-group"},
								{class, "error"}
							]},
							Context)
	end;

event(#postback{message={vault_lock, Args}}, Context) ->
	Name = proplists:get_value(name, Args),
	lock_key_session(Name, Context),
	z_render:wire({reload, []}, Context);

event(Event, Context) ->
	?DEBUG({unknown, Event}),
	Context.


manage_schema(install, Context) ->
	m_vault:init(Context).

%% @doc Generate a named public/private key for this system.
-spec generate_key(Name::string()|binary()|atom(), UserId::integer(), Password::string()|binary(), #context{}) 
 	 -> ok | {error, term()}.
generate_key(Name, UserId, Password, Context) ->
	case m_vault:is_key(Name, Context) of
		false ->
			case generate_key_pair() of
				{ok, PrivPEM, PubPEM} ->
					save_key(PrivPEM, PubPEM, Name, UserId, Password, Context);
				Err ->
					Err
			end;
		true ->
			{error, key_exists}
	end.

%% @doc Save the private and public pems in the database, using the user id and password.
save_key(PrivPEM, PubPEM, Name, UserId, Password, Context) ->
	RSAPrivKey = pem_to_key(PrivPEM),
	RSAPubKey = pem_to_key(PubPEM),
	m_vault:save_key(RSAPrivKey, RSAPubKey, Name, UserId, Password, Context).

-spec pem_to_key(binary()) -> #'RSAPrivateKey'{} | #'RSAPublicKey'{}.
pem_to_key(PEM) ->
	PemEntries = public_key:pem_decode(PEM),
	public_key:pem_entry_decode(hd(PemEntries)).


%% @doc Generate a private and public RSA PEM using openssl.
-spec generate_key_pair() -> {ok, RSAPrivPEM::binary(), RSAPubPEM::binary()} | {error, term()}.
generate_key_pair() ->
	OpenSSL = z_config:get(openssl, "openssl"),
	PrivCmd = iolist_to_binary([OpenSSL, " genrsa ", integer_to_list(?RSA_KEY_BITS)]),
	B = iolist_to_binary(os:cmd(binary_to_list(PrivCmd))),
	case binary:split(B, <<"-----BEGIN">>) of
		[_,PrivK] ->
			PrivateKey = <<"-----BEGIN", PrivK/binary>>,
			TmpFile = z_utils:tempfile(),
			case file:write_file(TmpFile, PrivateKey) of
				ok ->
					PubCmd = iolist_to_binary([OpenSSL, " rsa -in ", TmpFile ," -pubout"]),
					BP = iolist_to_binary(os:cmd(binary_to_list(PubCmd))),
					file:delete(TmpFile),
					case binary:split(BP, <<"-----BEGIN">>) of
						[_,PubK] -> 
							PublicKey = <<"-----BEGIN", PubK/binary>>,
							{ok, PrivateKey, PublicKey};
						_ ->
							{error, {openssl_error, BP}}
					end;
				Err ->
					file:delete(TmpFile),
					Err 
			end;
		_Other ->
			{error, {openssl_error, B}}
	end.


%% @doc Unlock the key, save it into the session.
-spec unlock_key_session(Name::string()|binary()|atom(), Password::string()|binary(), #context{}) -> ok.
unlock_key_session(Name, Password, Context) ->
	NameBin = z_convert:to_binary(Name), 
	case z_acl:user(Context) of
		undefined ->
			{error, no_user};
		UserId when is_integer(UserId) ->
			case m_vault:get_private_key(NameBin, UserId, Password, Context) of
				{ok, PrivateKey} ->
					Now = os:timestamp(),
					z_context:set_session({vault_key, NameBin}, {key, PrivateKey, Now, Now}, Context),
					ok;
				Error -> 
					Error
			end
	end.


%% @doc Forget the key in the session by resetting it to 'undefined'.
-spec lock_key_session(Name::string()|binary()|atom(), #context{}) -> ok.
lock_key_session(Name, Context) ->
	NameBin = z_convert:to_binary(Name), 
	z_context:set_session({vault_key, NameBin}, undefined, Context),
	ok.


%% @doc Get the current key from the session
%% @todo Do something with expiration of the key, after a period we want to have it locked automatically.
-spec get_key_session(Name::string()|binary()|atom(), #context{}) -> {ok, #'RSAPrivateKey'{}} | {error, not_found}.
get_key_session(Name, Context) ->
	NameBin = z_convert:to_binary(Name), 
	case z_context:get_session({vault_key, NameBin}, Context) of
		{key, PrivateKey, _DecodeTime, _LastUseTime} ->
			{ok, PrivateKey};
		undefined ->
			{error, not_found}
	end.


%% @doc Decode a term with the key in the session.
-spec decode_term_session(#vault{}, #context{}) -> {ok, term()} | {error, Reason::term()} | {locked, VaultName::binary()}.
decode_term_session(#vault{name=Name} = V, Context) ->
	case get_key_session(Name, Context) of
		{error, not_found} ->
			{locked, Name};
		{ok, Key} ->
			decode_term(V, Key)
	end.


%% @doc Encode a term using the named public key
-spec encode_term(Name::string()|binary()|atom(), Term::term(), #context{}) -> {ok, term()} | {error, not_found}.
encode_term(Name, Term, Context) ->
	NameBin = z_convert:to_binary(Name), 
	case m_vault:get_public_key(NameBin, Context) of
		{ok, #'RSAPublicKey'{} = PublicKey} ->
			Key = crypto:rand_bytes(16),
			IVec = crypto:rand_bytes(8), 
			Data = term_to_binary(Term), 
			Encoded = crypto:blowfish_cfb64_encrypt(Key, IVec, Data),
			Header = term_to_binary({blowfish_cfb64_encrypt, IVec, Key}),
			RsaHeader = public_key:encrypt_public(Header, PublicKey),
			{ok, #vault{name=NameBin, header=RsaHeader, data=Encoded, timestamp=os:timestamp()}};
		{error, _} = Err -> 
			Err
	end.


%% @doc Inspect a vault term, return the used vault name.
-spec get_encode_vault(#vault{}) -> {ok, binary()}.
get_encode_vault(#vault{name=Name}) ->
	{ok, Name}.


%% @doc Decode a term using the named public key
-spec decode_term(#vault{}, #'RSAPrivateKey'{}) -> {ok, term()} | {error, not_found}.
decode_term(#vault{header=Header, data=Data}, PrivateKey) ->
	case public_key:decrypt_private(Header, PrivateKey) of
		Hdr when is_binary(Hdr) ->
			case catch binary_to_term(Hdr) of
				{blowfish_cfb64_encrypt, IVec, Key} ->
					Decoded = crypto:blowfish_cfb64_decrypt(Key, IVec, Data),
					{ok, binary_to_term(Decoded)};
				_ ->
					{error, decode_header}
			end;
		_ ->
			{error, wrong_key}
	end.

-spec decode_term(#vault{}, integer(), string()|binary(), #context{}) -> {ok, term()} | {error, term()}.
decode_term(#vault{} = V, UserId, Password, Context) ->
	Name = get_encode_vault(V),
	case m_vault:get_private_key(Name, UserId, Password, Context) of
		{ok, PrivateKey} -> decode_term(V, PrivateKey);
		Error ->  Error
	end.


