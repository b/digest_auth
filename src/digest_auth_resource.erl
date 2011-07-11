%% @author Benjamin Black <b@b3k.us>
%% @copyright 2011 Benjamin Black.
%% @doc Digest auth example resource.

-module(digest_auth_resource).
-export([init/1, is_authorized/2, to_html/2]).

-include_lib("webmachine/include/webmachine.hrl").

-record(state, {realm, params}).

init([]) -> {ok, #state{realm="testrealm@boundary.com"}}.

is_authorized(ReqData, State=#state{realm=Realm}) ->
	Response = digest_auth:is_authorized(ReqData, Realm, fun digest_auth:get_password/2),
	{Response, ReqData, State}.
	
to_html(ReqData, State) ->
    {"<html><body>Hello, new world</body></html>", ReqData, State}.
