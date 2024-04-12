#!/usr/bin/env python
# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

from fortishield.tests.util import InitWDBSocketMock

with patch('fortishield.core.common.fortishield_uid'):
    with patch('fortishield.core.common.fortishield_gid'):
        from fortishield.core.mitre import *


@patch('fortishield.core.utils.FortishieldDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_FortishieldDBQueryMitreMetadata(mock_fdb):
    """Verify that the method connects correctly to the database and returns the correct type."""
    db_query = FortishieldDBQueryMitreMetadata()
    data = db_query.run()

    assert isinstance(db_query, FortishieldDBQueryMitre) and isinstance(data, dict)


@pytest.mark.parametrize('fdb_query_class', [
    FortishieldDBQueryMitreGroups,
    FortishieldDBQueryMitreMitigations,
    FortishieldDBQueryMitreReferences,
    FortishieldDBQueryMitreTactics,
    FortishieldDBQueryMitreTechniques,
    FortishieldDBQueryMitreSoftware

])
@patch('fortishield.core.utils.FortishieldDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_FortishieldDBQueryMitre_classes(mock_fdb, fdb_query_class):
    """Verify that the method connects correctly to the database and returns the correct types."""
    db_query = fdb_query_class()
    data = db_query.run()

    assert isinstance(db_query, FortishieldDBQueryMitre) and isinstance(data, dict)

    # All items have all the related_items (relation_fields) and their type is list
    try:
        assert all(
            isinstance(data_item[related_item], list) for related_item in db_query.relation_fields for data_item in
            data['items'])
    except KeyError:
        pytest.fail("Related item not found in data obtained from query")


@pytest.mark.parametrize('mitre_fdb_query_class', [
    FortishieldDBQueryMitreGroups,
    FortishieldDBQueryMitreMitigations,
    FortishieldDBQueryMitreReferences,
    FortishieldDBQueryMitreTactics,
    FortishieldDBQueryMitreTechniques,
    FortishieldDBQueryMitreSoftware
])
@patch('fortishield.core.utils.FortishieldDBConnection')
def test_get_mitre_items(mock_fdb, mitre_fdb_query_class):
    """Test get_mitre_items function."""
    info, data = get_mitre_items(mitre_fdb_query_class)

    db_query_to_compare = mitre_fdb_query_class()

    assert isinstance(info['allowed_fields'], set) and info['allowed_fields'] == set(
        db_query_to_compare.fields.keys()).union(
        db_query_to_compare.relation_fields).union(db_query_to_compare.extra_fields)
    assert isinstance(info['min_select_fields'], set) and info[
        'min_select_fields'] == db_query_to_compare.min_select_fields
