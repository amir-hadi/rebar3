-module(rebar_prv_compile_deps).

-behaviour(provider).

-export([init/1,
         do/1,
         format_error/1]).

-export([compile/2,
         compile/3]).

-include_lib("providers/include/providers.hrl").
-include("rebar.hrl").

-define(PROVIDER, 'compile-deps').
-define(ERLC_HOOK, erlc_compile).
-define(APP_HOOK, app_compile).
-define(DEPS, [lock]).

%% ===================================================================
%% Public API
%% ===================================================================

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    State1 = rebar_state:add_provider(State, providers:create([{name, ?PROVIDER},
                                                               {module, ?MODULE},
                                                               {bare, true},
                                                               {deps, ?DEPS},
                                                               {example, "rebar3 compile-deps"},
                                                               {short_desc, "Compile only the dependencies."},
                                                               {desc, "Compile only the dependencies."},
                                                               {opts, []}])),
    {ok, State1}.

-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, string()}.
do(State) ->
    DepsPaths = rebar_state:code_paths(State, all_deps),
    PluginDepsPaths = rebar_state:code_paths(State, all_plugin_deps),
    rebar_utils:remove_from_code_path(PluginDepsPaths),
    code:add_pathsa(DepsPaths),

    ProjectApps = rebar_state:project_apps(State),
    Providers = rebar_state:providers(State),
    Deps = rebar_state:deps_to_build(State),
    Cwd = rebar_state:dir(State),

    copy_and_build_apps(State, Providers, Deps),
    {ok, _} = rebar_digraph:compile_order(ProjectApps),

    %% Run top level hooks *before* project apps compiled but *after* deps are
    rebar_hooks:run_all_hooks(Cwd, pre, ?PROVIDER, Providers, State),
    {ok, State}.

-spec format_error(any()) -> iolist().
format_error({missing_artifact, File}) ->
    io_lib:format("Missing artifact ~ts", [File]);
format_error(Reason) ->
    io_lib:format("~p", [Reason]).

copy_and_build_apps(State, Providers, Apps) ->
    [build_app(State, Providers, AppInfo) || AppInfo <- Apps].

build_app(State, Providers, AppInfo) ->
    AppDir = rebar_app_info:dir(AppInfo),
    OutDir = rebar_app_info:out_dir(AppInfo),
    copy_app_dirs(AppInfo, AppDir, OutDir),
    compile(State, Providers, AppInfo).


compile(State, AppInfo) ->
    compile(State, rebar_state:providers(State), AppInfo).

compile(State, Providers, AppInfo) ->
    ?INFO("Compiling ~ts", [rebar_app_info:name(AppInfo)]),
    AppDir = rebar_app_info:dir(AppInfo),
    AppInfo1 = rebar_hooks:run_all_hooks(AppDir, pre, ?PROVIDER,  Providers, AppInfo, State),

    AppInfo2 = rebar_hooks:run_all_hooks(AppDir, pre, ?ERLC_HOOK, Providers, AppInfo1, State),
    rebar_erlc_compiler:compile(AppInfo2),
    AppInfo3 = rebar_hooks:run_all_hooks(AppDir, post, ?ERLC_HOOK, Providers, AppInfo2, State),

    AppInfo4 = rebar_hooks:run_all_hooks(AppDir, pre, ?APP_HOOK, Providers, AppInfo3, State),

    %% Load plugins back for make_vsn calls in custom resources.
    %% The rebar_otp_app compilation step is safe regarding the
    %% overall path management, so we can just load all plugins back
    %% in memory.
    PluginDepsPaths = rebar_state:code_paths(State, all_plugin_deps),
    code:add_pathsa(PluginDepsPaths),
    AppFileCompileResult = rebar_otp_app:compile(State, AppInfo4),
    %% Clean up after ourselves, leave things as they were.
    rebar_utils:remove_from_code_path(PluginDepsPaths),

    case AppFileCompileResult of
        {ok, AppInfo5} ->
            AppInfo6 = rebar_hooks:run_all_hooks(AppDir, post, ?APP_HOOK, Providers, AppInfo5, State),
            AppInfo7 = rebar_hooks:run_all_hooks(AppDir, post, ?PROVIDER, Providers, AppInfo6, State),
            has_all_artifacts(AppInfo5),
            AppInfo7;
        Error ->
            throw(Error)
    end.

%% ===================================================================
%% Internal functions
%% ===================================================================


has_all_artifacts(AppInfo1) ->
    case rebar_app_info:has_all_artifacts(AppInfo1) of
        {false, File} ->
            throw(?PRV_ERROR({missing_artifact, File}));
        true ->
            true
    end.

copy_app_dirs(AppInfo, OldAppDir, AppDir) ->
    case rebar_utils:to_binary(filename:absname(OldAppDir)) =/=
        rebar_utils:to_binary(filename:absname(AppDir)) of
        true ->
            EbinDir = filename:join([OldAppDir, "ebin"]),
            %% copy all files from ebin if it exists
            case filelib:is_dir(EbinDir) of
                true ->
                    OutEbin = filename:join([AppDir, "ebin"]),
                    filelib:ensure_dir(filename:join([OutEbin, "dummy.beam"])),
                    rebar_file_utils:cp_r(filelib:wildcard(filename:join([EbinDir, "*"])), OutEbin);
                false ->
                    ok
            end,

            filelib:ensure_dir(filename:join([AppDir, "dummy"])),

            %% link or copy mibs if it exists
            case filelib:is_dir(filename:join([OldAppDir, "mibs"])) of
                true ->
                    %% If mibs exist it means we must ensure priv exists.
                    %% mibs files are compiled to priv/mibs/
                    filelib:ensure_dir(filename:join([OldAppDir, "priv", "dummy"])),
                    symlink_or_copy(OldAppDir, AppDir, "mibs");
                false ->
                    ok
            end,
            {SrcDirs, ExtraDirs} = resolve_src_dirs(rebar_app_info:opts(AppInfo)),
            %% link to src_dirs to be adjacent to ebin is needed for R15 use of cover/xref
            [symlink_or_copy(OldAppDir, AppDir, Dir) || Dir <- ["priv", "include"] ++ SrcDirs],
            %% copy all extra_src_dirs as they build into themselves and linking means they
            %% are shared across profiles
            [copy(OldAppDir, AppDir, Dir) || Dir <- ExtraDirs];
        false ->
            ok
    end.

symlink_or_copy(OldAppDir, AppDir, Dir) ->
    Source = filename:join([OldAppDir, Dir]),
    Target = filename:join([AppDir, Dir]),
    rebar_file_utils:symlink_or_copy(Source, Target).

copy(OldAppDir, AppDir, Dir) ->
    Source = filename:join([OldAppDir, Dir]),
    Target = filename:join([AppDir, Dir]),
    case ec_file:is_dir(Source) of
        true  -> copy(Source, Target);
        false -> ok
    end.

%% TODO: use ec_file:copy/2 to do this, it preserves timestamps and
%% may prevent recompilation of files in extra dirs
copy(Source, Source) ->
    %% allow users to specify a directory in _build as a directory
    %% containing additional source/tests
    ok;
copy(Source, Target) ->
    %% important to do this so no files are copied onto themselves
    %% which truncates them to zero length on some platforms
    ok = delete_if_symlink(Target),
    ok = filelib:ensure_dir(filename:join([Target, "dummy.beam"])),
    {ok, Files} = rebar_utils:list_dir(Source),
    case [filename:join([Source, F]) || F <- Files] of
        []    -> ok;
        Paths -> rebar_file_utils:cp_r(Paths, Target)
    end.

delete_if_symlink(Path) ->
    case ec_file:is_symlink(Path) of
        true  -> file:delete(Path);
        false -> ok
    end.

resolve_src_dirs(Opts) ->
    SrcDirs = rebar_dir:src_dirs(Opts, ["src"]),
    ExtraDirs = rebar_dir:extra_src_dirs(Opts, []),
    normalize_src_dirs(SrcDirs, ExtraDirs).

%% remove duplicates and make sure no directories that exist
%% in src_dirs also exist in extra_src_dirs
normalize_src_dirs(SrcDirs, ExtraDirs) ->
    S = lists:usort(SrcDirs),
    E = lists:subtract(lists:usort(ExtraDirs), S),
    ok = warn_on_problematic_directories(S ++ E),
    {S, E}.

%% warn when directories called `eunit' and `ct' are added to compile dirs
warn_on_problematic_directories(AllDirs) ->
    F = fun(Dir) ->
        case is_a_problem(Dir) of
            true  -> ?WARN("Possible name clash with directory ~p.", [Dir]);
            false -> ok
        end
    end,
    lists:foreach(F, AllDirs).

is_a_problem("eunit") -> true;
is_a_problem("common_test") -> true;
is_a_problem(_) -> false.
