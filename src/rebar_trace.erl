%% -*- mode: erlang;erlang-indent-level: 4;indent-tabs-mode: nil -*-
%% ========================================================================
%% Copyright (c) 2016 T. R. Burghart
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%% ========================================================================

-module(rebar_trace).

-export([init/1, kill/0, stats/0, format_error/1]).

-define(TRACER,     rebar_tracer).
-define(TRACER_STR, "rebar_tracer").
-define(PROVIDER,   rebar_prv_trace).

-define(SHORT_DESC, "Rebar Tracer").
-define(LONG_DESC,  ?SHORT_DESC ".

Important:
 - Tracing is global, regardless of the profile it's configured in!
 - Tracing is heavyweight, use it ONLY for debugging!
 - Tracing WILL slow rebar down, possibly a LOT!

Configuration:
  The presence of the " ?TRACER_STR " configuration stanza in rebar.config
  enables tracing functionality. If the configuration is not present, the
  tracer is not initialized and has no effect. Recognized configuration
  elements are as follows:

{" ?TRACER_STR ", [
    {trace_file,    \"my_trace.txt\"},
    {trace_opts,    [call, return_to]},
    {trace_match,   [
        {rebar_core, '_', '_'},
        {{my_plugin, '_', '_'}, true, [local]}
    ]}
]}.

'trace_file': If specified, the path to the file into which trace records are
  written. If not specified, a file name is generated in the form
  \"" ?TRACER_STR ".NNN\" in the '/tmp' directory if it exists, or the current
  directory if it does not.

'trace_opts': Options to be passed in the 3rd parameter of erlang:trace/3. If
  not specified, options shown in the example above are the default. The 1st
  and 2nd parameters to erlang:trace/3 are Rebar's Pid and 'true',
  respectively. The tracing process runs under a separate Pid and is not
  itself traceable through this facility.

'trace_match': The list of match specifications provided to
  erlang:trace_pattern/3. If not specified, the tracer process will run, and
  the trace file will be created, but the facility will effectively be
  dormant unless match specifications are added dynamically.
  Each pattern consists of a tuple with 1, 2, or 3 elements, with the
  2nd and 3rd elements defaulting to 'true' and '[]' if not supplied. As a
  special case, a standalone MFA tuple will be effectively wrapped in '{}'
  and treated as above.
  WARNING: Specifying a match pattern of {'_', '_', '_'} is a VERY bad idea and
  will bring rebar to its knees!

References:
 - http://erlang.org/doc/man/erlang.html#trace-3
 - http://erlang.org/doc/man/erlang.html#trace_pattern-3

Command Line:
  The only supported command-line usage is simply \"" ?TRACER_STR "\", which
  displays the current configuration and minimal statistics.
").

-record(state, {
    outdev,
    rebar_pid,
    count       = 0,
    done_pid    = undefined,
    done_ref    = undefined,
    done_reply  = undefined
}).

%% ===================================================================
%% Public API
%% ===================================================================

-spec init(State :: rebar_state:t())
        -> {ok, rebar_state:t()} | {error, {?MODULE, term()}}.
%%
%% @doc Installs the trace handler.
%%
init(State) ->
    %
    % Alas, the #provider{} record isn't publicly defined, but we know the
    % first two fields after the record tag are the name and module.
    %
    case lists:keyfind(?TRACER, 2, rebar_state:providers(State)) of
        false ->
            % not installed yet
            case tracer_init(State) of
                {error, {?MODULE, _}} = Err ->
                    Err;
                {error, Reason} ->
                    {error, {?MODULE, Reason}};
                _ ->
                    % install the provider even if the tracer itself isn't
                    % configured so it'll show up in help
                    Prov = providers:create([
                        {name,          ?TRACER},
                        {module,        ?PROVIDER},
                        {bare,          true},
                        {deps,          []},
                        {example,       example(State)},
                        {opts,          []},
                        {short_desc,    ?SHORT_DESC},
                        {desc,          ?LONG_DESC}
                    ]),
                    {ok, rebar_state:add_provider(State, Prov)}
            end;
        Rec ->
            case erlang:element(3, Rec) of
                ?PROVIDER ->
                    ok;
                Mod ->
                    rebar_api:warn(
                        "provider '~s' already installed as module '~s', "
                        "skipping install as module '~s'",
                        [?TRACER, Mod, ?MODULE])
            end,
            {ok, State}
    end.

-spec kill() -> ok | {error, {?MODULE, term()}}.
%%
%% @doc Shut down the tracer if it's running.
%%
kill() ->
    case tracer_kill(erlang:self()) of
        {error, {?MODULE, _}} = Err ->
            Err;
        {error, Reason} ->
            {error, {?MODULE, Reason}};
        _ ->
            ok
    end.

-spec stats() -> {?TRACER, [{atom(), term()}]} | {error, {?MODULE, not_running}}.
%%
%% @doc Return the tracer configuration.
%%
stats() ->
    case tracer_stats(erlang:self()) of
        {error, {?MODULE, _}} = Err ->
            Err;
        {error, Reason} ->
            {error, {?MODULE, Reason}};
        Stats ->
            {?TRACER, Stats}
    end.

-spec format_error(Error :: term()) -> string().
%%
%% @doc Converts specified Error to a string.
%%
format_error(Error) ->
    lists:flatten(io_lib:format("~s: ~p", [?MODULE, Error])).

%% ===================================================================
%% Internal
%% ===================================================================

example(State) ->
    Exec = case rebar_state:escript_path(State) of
        undefined ->
            "rebar3";
        Path ->
            lists:last(filename:split(Path))
    end,
    lists:flatten(io_lib:format("~s ~s", [Exec, ?TRACER])).

tracer_init(State) ->
    case erlang:whereis(?TRACER) of
        undefined ->
            case rebar_state:get(State, ?TRACER, []) of
                [] ->
                    no_config;
                Config ->
                    rebar_api:debug("~s: Config:~n~p", [?TRACER, Config]),
                    ThisPid = erlang:self(),
                    Tracer  = erlang:spawn(erlang, apply,
                        [fun tracer_proc/3, [ThisPid, ThisPid, Config]]),
                    receive
                        {?TRACER, running, ThisPid} ->
                            erlang:register(?TRACER, Tracer),
                            ok
                    after
                        10000 ->
                            rebar_api:error("~s failed to start", [?TRACER]),
                            erlang:exit(Tracer, timeout),
                            {error, timeout}
                    end
            end;
        _ ->
            ok
    end.

tracer_kill(ReplyTo) ->
    case erlang:whereis(?TRACER) of
        undefined ->
            not_running;
        Tracer ->
            Tracer ! {'EXIT', ReplyTo, normal},
            receive
                {closed, Tracer, Status} ->
                    Status
            end
    end.

tracer_stats(ReplyTo) ->
    case erlang:whereis(?TRACER) of
        undefined ->
            rebar_api:warn("~s is not running!", [?TRACER]),
            [];
        Tracer ->
            Tracer ! {tracer_stats, ReplyTo},
            receive
                {tracer_stats, Tracer, Stats} ->
                    Stats
            end
    end.

tracer_proc(RebarPid, Starter, Config) ->
    {Gen, File} = case proplists:get_value(trace_file, Config) of
        undefined ->
            {true, gen_output_file()};
        TraceFile ->
            case filelib:ensure_dir(TraceFile) of
                ok ->
                    {false, TraceFile};
                {error, Reason} ->
                    FN  = gen_output_file(),
                    rebar_api:warn(
                        "~s: error ~p creating directory for \"~s\", "
                        "using \"~s\" instead.",
                        [?TRACER, Reason, TraceFile, FN]),
                    {true, FN}
            end
    end,
    Opts = proplists:get_value(trace_opts, Config, [call, return_to]),
    try
        erlang:trace(RebarPid, true, Opts)
    catch
        error:What ->
            rebar_api:abort(
                "~s: fatal error ~p initializing trace with options ~p",
                [?TRACER, What, Opts])
    end,
    erlang:put({?TRACER, trace_opts}, Opts),
    Filters = proplists:get_value(trace_match, Config, []),
    lists:foreach(fun set_trace/1, Filters),
    {OutFile, OutDev} = open_output_file(Gen, File),
    erlang:put({?TRACER, trace_file}, OutFile),
    erlang:process_flag(trap_exit, true),
    erlang:process_flag(priority, high),
    % tell the starter it's running
    Starter ! {?TRACER, running, RebarPid},
    tracer_recv(#state{outdev = OutDev, rebar_pid = RebarPid}).

set_trace({M, F, _} = MFA)
        when erlang:is_atom(M) andalso erlang:is_atom(F) ->
    set_trace({MFA, true});

set_trace({MFA}) ->
    set_trace({MFA, true});

set_trace({MFA, MatchSpec}) ->
    set_trace({MFA, MatchSpec, []});

set_trace({MFA, MatchSpec, Flags} = Filt) ->
    try
        erlang:trace_pattern(MFA, MatchSpec, Flags),
        Filts = case erlang:get({?TRACER, filters}) of
            undefined ->
                [];
            List ->
                proplists:delete(MFA, List)
        end,
        erlang:put({?TRACER, filters}, [{MFA, {MatchSpec, Flags}} | Filts]),
        ok
    catch
        error:What ->
            rebar_api:warn(
                "~s: error ~p setting trace pattern ~p, skipping",
                [?TRACER, What, Filt]),
            {error, {?MODULE, What}}
    end.

%
% messages are handled in the order received, no filtering
%
tracer_recv(State) ->
    receive
        Msg ->
            handle_msg(State, Msg)
    end.

handle_msg(#state{
        outdev = OutDev, count = Count} = State, {trace, _Pid, Op, MFA}) ->
    io:format(OutDev, "~p: ~p~n", [Op, MFA]),
    tracer_recv(State#state{count = (Count + 1)});

handle_msg(#state{count = Count} = State, {tracer_stats, ReplyTo}) ->
    Stats = [{count, Count} | tracer_config(erlang:get(), [])],
    ReplyTo ! {tracer_stats, erlang:self(), Stats},
    tracer_recv(State);

handle_msg(#state{
        outdev      = OutDev,
        rebar_pid   = RebarPid,
        done_pid    = DonePid,
        done_ref    = DoneRef,
        done_reply  = DoneReply },
        {trace_delivered, RebarPid, DoneRef}) ->
    io:put_chars(OutDev, "Tracing completed.\n"),
    file:close(OutDev),
    DonePid ! {closed, erlang:self(), DoneReply},
    erlang:exit(normal);

handle_msg(#state{rebar_pid = RebarPid} = State, {'EXIT', From, Why}) ->
    Ref = erlang:trace_delivered(RebarPid),
    tracer_recv(State#state{
        done_pid = From, done_ref = Ref, done_reply = Why});

handle_msg(State, {set_trace, ReplyTo, Spec}) ->
    ReplyTo ! {set_trace, Spec, erlang:self(), set_trace(Spec)},
    tracer_recv(State);

handle_msg(State, Msg) ->
    rebar_api:debug("~s: unhandled message: ~p", [?TRACER, Msg]),
    tracer_recv(State).

tracer_config([{{?TRACER, Key}, Val} | Rest], Result) ->
    tracer_config(Rest, [{Key, Val} | Result]);

tracer_config([_KV | Rest], Result) ->
    tracer_config(Rest, Result);

tracer_config([], Result) ->
    Result.

open_output_file(false, File) ->
    case file:open(File, [write]) of
        {ok, IoDev} ->
            {File, IoDev};
        {error, Reason} ->
            FN  = gen_output_file(),
            rebar_api:warn(
                "~s: error ~p opening \"~s\", "
                "using \"~s\" instead.",
                [?TRACER, Reason, File, FN]),
            open_output_file(true, FN)
    end;

open_output_file(true, File) ->
    case file:open(File, [write]) of
        {ok, IoDev} ->
            {File, IoDev};
        {error, Reason} ->
            rebar_api:abort(
                "~s: fatal error ~p opening output file \"~s\"",
                [?TRACER, Reason, File])
            % doesn't return
    end.

gen_output_file() ->
    FN  = io_lib:format("~s.~b", [?TRACER,
            erlang:phash2([erlang:self(), os:timestamp()])]),
    FP  = case filelib:is_dir("/tmp") of
        true ->
            filename:join("/tmp", FN);
        _ ->
            FN
    end,
    lists:flatten(FP).




