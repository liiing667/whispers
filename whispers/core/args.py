import logging
from argparse import ArgumentParser, Namespace
from functools import wraps
from sys import argv, exit, stdout

from whispers.__version__ import __version__, __whispers__
from whispers.core.constants import DEFAULT_PATH


def argument_parser() -> ArgumentParser:
    """CLI argument parser"""
    args_parser = ArgumentParser("whispers", description=("Identify secrets in static structured text."))
    args_parser.add_argument("--info", action="store_true", help="show extended help and exit")
    args_parser.add_argument("--version", action="version", version=__version__, help="show version and exit")
    args_parser.add_argument("--init", default=False, action="store_true", help="make config and exit")
    args_parser.add_argument("--dump", action="store_true", help="dump AST and exit")
    args_parser.add_argument("-a", "--ast", action="store_true", help="enable AST analysis")
    args_parser.add_argument("-c", "--config", default=None, help="config filename")
    args_parser.add_argument("-o", "--output", default=None, help="output filename")
    args_parser.add_argument("-l", "--log", default=None, help="log filename")
    args_parser.add_argument("--git", action="store_true", help="scan Git history")
    args_parser.add_argument(
        "--git-history",
        "--history",
        dest="git_history",
        action="store_true",
        help="scan Git history",
    )
    args_parser.add_argument(
        "--git-range",
        "--history-range",
        "--rev-range",
        "--revision",
        dest="git_range",
        default=None,
        help="Git revision or range to scan (default: HEAD)",
    )
    args_parser.add_argument(
        "--git-state",
        "--history-state",
        "--state-file",
        "--state",
        "--git-state-file",
        "--history-checkpoint",
        dest="git_state",
        default=None,
        help="resumable Git history state file",
    )
    args_parser.add_argument(
        "--git-resume",
        "--resume",
        dest="git_resume",
        action="store_true",
        help="resume the frozen Git history generation",
    )
    args_parser.add_argument(
        "--git-reset",
        "--reset",
        dest="git_reset",
        action="store_true",
        help="start a new Git history generation",
    )
    args_parser.add_argument(
        "--git-depth",
        "--history-depth",
        "--max-commits",
        dest="git_depth",
        type=int,
        default=None,
        help="maximum number of commits in the history snapshot",
    )
    args_parser.add_argument(
        "--git-repo",
        "--repo",
        dest="git_repo",
        default=None,
        help="Git repository to scan (defaults to src)",
    )
    args_parser.add_argument(
        "-v",
        "--verbose",
        action="store_const",
        const=logging.INFO,
        default=None,
        help="show info log",
    )
    args_parser.add_argument(
        "--debug",
        action="store_const",
        const=logging.DEBUG,
        default=None,
        help="show debug log",
    )
    args_parser.add_argument("-e", "--exitcode", default=0, type=int, help="exit code on success")
    args_parser.add_argument("-f", "--files", default=None, help="csv of globs for including files")
    args_parser.add_argument("-F", "--xfiles", default=None, help="regex for excluding files")
    args_parser.add_argument("-g", "--groups", default=None, help="csv of rule groups to report (see --info)")
    args_parser.add_argument("-G", "--xgroups", default=None, help="csv of rule groups to exclude (see --info)")
    args_parser.add_argument("-r", "--rules", default=None, help="csv of rule IDs to report (see --info)")
    args_parser.add_argument("-R", "--xrules", default=None, help="csv of rule IDs to exclude (see --info)")
    args_parser.add_argument("-s", "--severity", default=None, help="csv of severity levels to report (see --info)")
    args_parser.add_argument("-S", "--xseverity", default=None, help="csv of severity levels to exclude (see --info)")
    args_parser.add_argument("src", nargs="*", help="target file or directory")

    args_parser.print_help = show_splash(args_parser.print_help)

    return args_parser


def parse_args(arguments: list = argv[1:]) -> Namespace:
    """Parses a list into a namespace"""
    args, _ = argument_parser().parse_known_args(arguments)

    if args.info:
        show_info()
        exit()

    if args.init:
        show_config()
        exit()

    if not args.src and args.git_repo:
        args.src = args.git_repo

    if not args.src:
        argument_parser().print_help()
        exit()
    else:
        args.src = args.src[0]

    if args.dump:
        from whispers.plugins.semgrep import AST

        print(AST.dump(args.src))
        exit()

    if args.log:
        args.log = logging.FileHandler(args.log, mode="w")
    else:
        args.log = logging.StreamHandler()

    log_level = args.debug or args.verbose or logging.WARNING
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=log_level, handlers=[args.log])

    if args.output:
        args.output = open(args.output, "w")
    else:
        args.output = stdout

    if args.files:
        args.files = args.files.split(",")

    if args.xfiles:
        from whispers.core.utils import load_regex

        args.xfiles = load_regex(args.xfiles)

    if args.rules:
        args.rules = args.rules.split(",")

    if args.xrules:
        args.xrules = args.xrules.split(",")

    if args.groups:
        args.groups = args.groups.split(",")

    if args.xgroups:
        args.xgroups = args.xgroups.split(",")

    if args.severity:
        args.severity = args.severity.split(",")

    if args.xseverity:
        args.xseverity = args.xseverity.split(",")

    # Keep the history switches aliases of one accepted operation.
    args.git_history = bool(args.git or args.git_history)
    args.history = args.git_history
    args.git = args.git_history
    if args.git_range:
        args.git_history = True
        args.history = True
        args.git = True

    args.state = args.git_state
    args.history_state = args.git_state
    args.history_state_path = args.git_state
    args.git_state_path = args.git_state
    args.rev_range = args.git_range
    args.revision = args.git_range
    args.git_ref = args.git_range
    args.history_revision = args.git_range
    args.max_commits = args.git_depth

    return args


def show_splash(func, **kwargs):
    @wraps(func)
    def splash(*args, **kwargs):
        print(__whispers__)
        print(__version__.rjust(64), end="\n\n")
        return func(*args, **kwargs)

    return splash


def show_config():
    print(DEFAULT_PATH.joinpath("config.yml").read_text())


def show_info():
    from whispers.core.utils import default_rules

    argument_parser().print_help()
    rules_table = []
    col_width = 20
    for rule in default_rules():
        line = (
            "    "
            + rule["group"].ljust(col_width)[:col_width]
            + " | "
            + rule["id"].ljust(col_width)[:col_width]
            + " | "
            + rule["severity"].ljust(col_width)[:col_width]
        )
        rules_table.append(line)

    draw_line = "\n  " + ("+--" + "-" * col_width) * 3 + "+"
    print(
        "\n\nrules:\n"
        + draw_line
        + "\n  | "
        + "group".ljust(col_width)
        + " | "
        + "rule id".ljust(col_width)
        + " | "
        + "severity".ljust(col_width)
        + " |"
        + draw_line
        + "\n"
        + "\n".join(sorted(rules_table))
        + draw_line
        + "\n\nreadme:  https://github.com/adeptex/whispers\n"
    )
