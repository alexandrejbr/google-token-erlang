%% @author <ruel@ruel.me>
%% @copyright 2016 Ruel Pagayon
%% @doc The google_token application verifies the integrity of
%% Google ID tokens in accordance with Google's criterias.
%% See: https://developers.google.com/identity/sign-in/web/backend-auth
-module(google_token).
-behaviour(gen_server).

%% API
-export([validate/1,
         validate/2
        ]).

%% External functions
-export([start_link/0]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-export([get_pub_keys/0]).

-type keys() :: #{exp_at := integer(), keys := list()}.

%% ----------------------------------------------------------------------------
%% External functions
%% ----------------------------------------------------------------------------

%% @private
%% @doc Start gen_server
start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% ----------------------------------------------------------------------------
%% API
%% ----------------------------------------------------------------------------

-spec validate(binary()) -> {valid, map()} | {invalid, term()}.
%% @doc Validates the ID token
validate(IdToken) ->
  [{keys, #{exp_at := ExpAt, keys := Keys}}] =
  case ExpAt > now_gregorian_seconds() of
    false ->
      do_verify(IdToken, Keys);
    true ->
      #{keys := RefreshedKeys} = refresh_keys(),
      do_verify(IdToken, RefreshedKeys),
      ok
  end.

-spec refresh_keys() -> keys().
refresh_keys() ->
  gen_server:call(?MODULE, refresh).

-spec validate(binary(), list()) -> {valid, map()} | {invalid, term()}.
%% @doc Validates the ID token and it's aud against the client IDs specified
validate(IdToken, ClientIds) ->
  gen_server:call(?MODULE, {verify_with_ids, [IdToken, ClientIds]}).

%% ----------------------------------------------------------------------------
%% gen_server callbacks
%% ----------------------------------------------------------------------------

%% @private
init(_Args) ->
  ets:new(google_token_cache, [set, public, named_table, {read_concurrency, true}]),
  InitialState = #{exp_at => 0, keys => []},
  ets:insert(google_token_cache, InitialState),
  {ok, InitialState}.

%% @private
handle_call(refresh, _From, #{exp_at := ExpAt} = State) ->
  case ExpAt > now_gregorian_seconds() of
    true -> {reply, State, State};
    false ->
      NewState = get_pub_keys(),
      ets:insert(google_token_cache, NewState),
      {reply, NewState, NewState}
  end;
handle_call({verify_with_ids, [IdToken, ClientIds]}, _From, State) ->
  Reply = case do_verify(IdToken, State) of
    {valid, Payload} ->
      check_audience(Payload, ClientIds);
    Error ->
      Error
  end,
  {reply, Reply, State};
handle_call(_Request, _From, State) ->
  {reply, ok, State}.

%% @private
handle_cast(_Message, State) ->
  {noreply, State}.

%% @private
handle_info(_Info, State) ->
  {noreply, State}.

%% @private
terminate(_Reason, _State) ->
  ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%% ----------------------------------------------------------------------------
%% Internal functions
%% ----------------------------------------------------------------------------

-spec do_verify(binary(), [map()]) -> {valid, map()} |
                                      {invalid, term()} |
                                      {error, term()}.
%% @private
%% @doc Abstracts the JWT validation
do_verify(IdToken, Keys) ->
  try get_kid(IdToken) of
    {kid, KId} ->
      try_verify(IdToken, KId, Keys);
    {error, not_found} ->
      {invalid, malformed_token}
  catch
    _Error:_Reason ->
      {invalid, malformed_token}
  end.

-spec get_kid(binary()) -> {kid, binary()} | {error, not_found}.
%% @private
%% @doc Gets the kid parameter from the IdToken
get_kid(IdToken) ->
  Protected = jose_jwt:peek_protected(IdToken),
  {_M, Map} = jose_jws:to_map(Protected),
  case maps:is_key(<<"kid">>, Map) of
    true ->
      {kid, maps:get(<<"kid">>, Map)};
    false ->
      {error, not_found}
  end.

try_verify(IdToken, KId, Keys) ->
  case find_key(KId, Keys) of
    {key, Key} ->
      validate_jwt(Key, IdToken);
    _Error when Retried =:= false ->
      try_verify(IdToken, KId, State, [], false);
    _Error ->
      {invalid, no_verifier}
  end.

-spec validate_jwt(map(), binary()) -> {valid, map()} | {invalid, term()}.
%% @private
%% @doc Does the actual validation of JWT using given JWK
validate_jwt(Key, JWT) ->
  JWK = jose_jwk:from_map(Key),
  case jose_jwt:verify(JWK, JWT) of
    {true, {jose_jwt, Payload}, _JWS} ->
      validate_claims(Payload);
    {false, _Payload, _JWS} ->
      {invalid, unverified}
  end.

-spec validate_claims(map()) -> {valid, map()} | {invalid, term()}.
%% @private
%% @doc Validate expiry and issuer claims
validate_claims(Payload) ->
  Expiry = maps:get(<<"exp">>, Payload, 0),
  Now    = erlang:round(erlang:system_time() / 1000000000),
  if
    Now < Expiry ->
      check_issuer(Payload);
    true ->
      {invalid, expired}
  end.

-spec check_issuer(map()) -> {valid, map()} | {invalid, term()}.
%% @private
%% @doc Check iss and match with Google's known iss
check_issuer(Payload) ->
  Issuer = maps:get(<<"iss">>, Payload, <<>>),
  if
    Issuer =:= <<"accounts.google.com">> orelse
    Issuer =:= <<"https://accounts.google.com">> ->
      {valid, Payload};
    true ->
      {invalid, wrong_iss}
  end.

-spec check_audience(map(), list()) -> {valid, map()} | {invalid, term()}.
%% @private
%% @doc Check aud claim and match with given ids
check_audience(Payload, Ids) ->
  Audience = maps:get(<<"aud">>, Payload, <<>>),
  Found = lists:foldl(fun(Id, Found) ->
    BinId = ensure_binary(Id),
    Found orelse Audience =:= BinId
  end, false, Ids),
  if
    Found ->
      {valid, Payload};
    true ->
      {invalid, wrong_aud}
  end.


-spec find_key(binary(), list()) -> {key, map()} | {error, not_found}.
%% @private
%% @doc Search Google's key / cert list for kid
find_key(KId, Keys) ->
  find_key(KId, Keys, no_match).
find_key(_KId, _Keys, {match, Key}) ->
  {key, Key};
find_key(_KId, [], _Match) ->
  {error, not_found};
find_key(KId, [Key | Keys], no_match) ->
  MKId = maps:get(<<"kid">>, Key, undefined),
  Res = case MKId of
    KId ->
      {match, Key};
    MKId ->
      no_match
  end,
  find_key(KId, Keys, Res).

%% @private
%% @doc Gets the latest JWK from Google's certificate repository
-spec get_pub_keys() -> keys().
get_pub_keys() ->
  Url = <<"https://www.googleapis.com/oauth2/v3/certs">>,
  case hackney:request(get, Url, [], <<>>, [with_body]) of
    {ok, 200, Headers, Body} ->
      BodyMap = jsx:decode(Body, [return_maps]),
      Keys = maps:get(<<"keys">>, BodyMap, []),
      CacheControl = hackney_headers:parse(<<"Cache-Control">>, Headers),
      {match, [MaxAgeBin]} = re:run(CacheControl,
                                    <<"max-age=(\\d+)">>,
                                    [{capture, all_but_first, binary}]),
      MaxAge = binary_to_integer(MaxAgeBin),
      #{exp_at => now_gregorian_seconds() + MaxAge, keys => Keys};
    {ok, _, _, _} ->
      {error, service_unavailable};
    {error, Reason} ->
      {error, Reason}
  end.

now_gregorian_seconds() ->
  calendar:datetime_to_gregorian_seconds(calendar:local_time()).

-spec ensure_binary(term()) -> binary().
%% @private
%% @doc Converts a list, atom, or integer to binary if necessary
ensure_binary(Term) when is_binary(Term) ->
  Term;
ensure_binary(Term) when is_integer(Term) ->
  integer_to_binary(Term);
ensure_binary(Term) when is_list(Term) ->
  list_to_binary(Term);
ensure_binary(Term) when is_atom(Term) ->
  atom_to_binary(Term, utf8).

%%%_* Emacs ============================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
