%% @author <ruel@ruel.me>
%% @copyright 2016 Ruel Pagayon
%% @doc Supervisor for the main google_token server
-module(google_token_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
  supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
  SupFlags = #{strategy => one_for_one, intensity => 1000, period => 1},

  ChildSpecs = [#{id => google_token,
                 start => {google_token, start_link, []},
                 restart => permanent,
                 shutdown => 5000,
                 type => worker,
                 modules => [google_token]
                }
               ],
  {ok, {SupFlags, ChildSpecs}}.
