"""Atheris harness for plan dependency/output graph validation."""

import json
import sys

import atheris

from scripts.plan_graph import validate_output_links


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzDataProvider(data)
    document = fdp.ConsumeUnicodeNoSurrogates(4096)
    try:
        plan = json.loads(document)
    except json.JSONDecodeError:
        return
    if not isinstance(plan, (dict, list)):
        return
    try:
        validate_output_links(plan)
    except (TypeError, ValueError):
        return


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
