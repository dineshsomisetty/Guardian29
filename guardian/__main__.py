"""`python -m guardian` entry point: hands the command line to guardian.cli.main and exits with its return code.

See guardian/cli.py for the list of subcommands (run, plans, decide, decide-batch, serve-runs, api, watch).
"""
import sys

from guardian.cli import main

sys.exit(main())
