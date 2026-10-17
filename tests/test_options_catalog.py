from dataclasses import FrozenInstanceError
from typing import get_args

import pytest

from app.nmap.options_catalog import (
    OS_DETECTION,
    SCAN_TYPES,
    SERVICE_DETECTION,
    TIMING_TEMPLATES,
    XML_OUTPUT_ARGS,
)
from app.schemas.scan import ScanRequest, ScanType


def all_options():
    return [*SCAN_TYPES.values(), SERVICE_DETECTION, OS_DETECTION, *TIMING_TEMPLATES.values()]


def test_every_scan_type_in_schema_has_a_catalog_entry():
    assert set(get_args(ScanType)) == set(SCAN_TYPES)


def test_timing_range_in_schema_matches_catalog():
    timing_field = ScanRequest.model_fields["timing"]
    bounds = {type(m).__name__: m for m in timing_field.metadata}

    assert set(TIMING_TEMPLATES) == set(range(bounds["Ge"].ge, bounds["Le"].le + 1))


def test_root_only_options():
    root_flags = {option.flag for option in all_options() if option.requires_root}

    assert root_flags == {"-sS", "-sU", "-O"}


def test_every_flag_is_one_token():
    for option in all_options():
        assert option.flag.startswith("-")
        assert " " not in option.flag
        assert "=" not in option.flag


def test_xml_output_goes_to_stdout():
    assert XML_OUTPUT_ARGS == ("-oX", "-")


def test_options_are_immutable():
    with pytest.raises(FrozenInstanceError):
        SCAN_TYPES["connect"].flag = "--script=vuln"
