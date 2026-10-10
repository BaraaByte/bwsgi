"""Serv00 / Passenger entrypoint."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from run_local import app as application
