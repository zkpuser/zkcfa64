"""Determinize ZEKRA's source discovery without modifying upstream code."""

import os

_listdir = os.listdir
os.listdir = lambda *args, **kwargs: sorted(_listdir(*args, **kwargs))
