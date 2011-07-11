-module(nonce_cache).
-behaviour(gen_server).

-export([start/0, start/1, init/1]).
-export([handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export([insert/2, insert/3, validate/1, expire/1]).

-record(state, {ets_db}).

% n   -> nonce
% o   -> opaque
% ts  -> timestamp
% nc  -> nonce use counter
% max -> max uses
-record(nonce, {n, o, ts, nc, max}).

-define(NONCE_LIFETIME, 60000).
-define(MAX_INT, 4294967295).

start() -> start([]).

start(Config) ->
  gen_server:start({local, ?MODULE}, ?MODULE, [Config], []).

init(_Config) ->
  EtsDb = ets:new(nonces,
                  [set, protected, {keypos, 2},
                   {heir, none}, {write_concurrency, false},
                   {read_concurrency, false}]),
  {ok, #state{ets_db=EtsDb}}.

handle_call({insert, Nonce, Opaque, Options}, _From, State=#state{ets_db=EtsDb}) ->
  Max = proplists:get_value(max, Options, ?MAX_INT),
  Lifetime = proplists:get_value(lifetime, Options, ?NONCE_LIFETIME),
  ets:insert(EtsDb, #nonce{
    n=Nonce,
    o=Opaque,
    ts=timestamp(),
    nc=0,
    max=Max
  }),
  erlang:send_after(Lifetime, self(), {expire, Nonce}),
  {reply, ok, State};

handle_call({validate, Params}, _From, State=#state{ets_db=EtsDb}) ->
  Nonce = proplists:get_value(nonce, Params),
  Response = case ets:lookup(EtsDb, Nonce) of
    [NR=#nonce{o=Opaque,nc=NC,max=Max}] ->
      Opaque2 = proplists:get_value(opaque, Params),
      NC2 = proplists:get_value(nc, Params),
      case validate(Opaque == Opaque2,
               NC == (erlang:list_to_integer(NC2) - 1),
               NC < Max,
               digest_auth:is_valid(Params)) of
        ok ->
          ets:insert(EtsDb, NR#nonce{nc=NC2}),
          ok;
        Error -> Error
      end;
    _ -> {expired, Nonce}
  end,
  {reply, Response, State}.

validate(true, true, true, true) -> ok;
validate(false, _, _, _) -> {error, "Bad opaque"};
validate(_, false, _, _) -> {error, "Bad nonce count"};
validate(_, _, false, _) -> {error, "Max count reached"};
validate(_, _, _, false) -> {error, "Invalid response"}.

handle_cast(_, State) -> {noreply, State}.

handle_info({expire, Nonce}, State=#state{ets_db=EtsDb}) ->
  ets:delete(EtsDb, Nonce),
  {noreply, State};
handle_info(_Info, State) -> {noreply, State}.

terminate(_, _) -> ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

insert(Nonce, Opaque) -> insert(Nonce, Opaque, []).
insert(Nonce, Opaque, Options) -> gen_server:call(nonce_cache, {insert, Nonce, Opaque, Options}).

validate(Params) -> gen_server:call(nonce_cache, {validate, Params}).

timestamp() ->
  calendar:datetime_to_gregorian_seconds(calendar:universal_time()) -
    calendar:datetime_to_gregorian_seconds( {{1970,1,1},{0,0,0}} ).
  
expire(Nonce) -> ets:delete(nonces, Nonce).