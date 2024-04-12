#!/usr/bin/env python
# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import patch, MagicMock

import pytest

from fortishield.tests.util import InitWDBSocketMock

with patch('fortishield.core.common.fortishield_uid'):
    with patch('fortishield.core.common.fortishield_gid'):
        sys.modules['fortishield.rbac.orm'] = MagicMock()
        import fortishield.rbac.decorators
        del sys.modules['fortishield.rbac.orm']

        from fortishield.tests.util import RBAC_bypasser
        fortishield.rbac.decorators.expose_resources = RBAC_bypasser
        from fortishield import syscollector
        from fortishield.core.results import AffectedItemsFortishieldResult
        from fortishield.core.syscollector import Type, get_valid_fields


# Tests

@pytest.mark.parametrize("select, search", [
    (None, None),
    (['hostname', 'os.name'], None),
    (None, {'negation': False, 'value': 'Centos'}),
])
@patch('fortishield.core.utils.path.exists', return_value=True)
@patch('fortishield.syscollector.get_agents_info', return_value=['000', '001'])
@patch('fortishield.core.agent.Agent.get_basic_information', return_value=None)
@patch('fortishield.core.agent.Agent.get_agent_os_name', return_value='Linux')
def test_get_item_agent(mock_agent_attr, mock_basic_info, mock_agents_info, mock_exists, select, search):
    """Test get_item_agent method.

    Verify that the get_item method returns an appropriate
    and expected result after searching in the database.

    Parameters
    ----------
    select : list
        Fields to be returned when searching in DB
    search : dict
        Looks for items with the specified string in DB.
    """
    with patch('fortishield.core.utils.FortishieldDBConnection') as mock_fdb:
        mock_fdb.return_value = InitWDBSocketMock(sql_schema_file='schema_syscollector_000.sql')
        results = syscollector.get_item_agent(agent_list=['000'], offset=0, select=select, search=search)

        assert isinstance(results, AffectedItemsFortishieldResult)
        assert results.render()['data']['failed_items'] == [], 'No failed_items should be returned'
        for result in results.render()['data']['affected_items']:
            if select:
                assert len(result.keys()) == len(select) + 1, f'"Select" not returning {len(select)} +1 elements.'
            if search:
                assert search['value'] in result['os']['name'], f'{search["value"]} not in result.'


@pytest.mark.parametrize("agent_list, expected_exception", [
    (['010'], 1701),
])
@patch('fortishield.syscollector.get_agents_info', return_value=['000', '001'])
@patch('fortishield.core.agent.Agent.get_basic_information', return_value=None)
@patch('fortishield.core.agent.Agent.get_agent_os_name', return_value='Linux')
def test_failed_get_item_agent(mock_agent_attr, mock_basic_info, mock_agents_info, agent_list, expected_exception):
    """Test if get_item_agent method handle exceptions properly.

    Parameters
    ----------
    agent_list : list
        List of agents IDs to search
    expected_exception : int
        Expected error code when triggering the exception.
    """
    with patch('fortishield.core.utils.FortishieldDBConnection') as mock_fdb:
        mock_fdb.return_value = InitWDBSocketMock(sql_schema_file='schema_syscollector_000.sql')
        results = syscollector.get_item_agent(agent_list=agent_list, offset=0, limit=500, nested=False)

        assert expected_exception == results.render()['data']['failed_items'][0]['error']['code'], \
            'Error code not expected'


@pytest.mark.parametrize("element_type", [
    'hardware',
    'packages',
    'processes',
    'ports',
    'netaddr',
    'netproto',
    'netiface',
    'hotfixes'
])
@patch('fortishield.core.utils.path.exists', return_value=True)
@patch('fortishield.syscollector.get_agents_info', return_value=['000', '001'])
@patch('fortishield.core.agent.Agent.get_basic_information', return_value=None)
@patch('fortishield.core.agent.Agent.get_agent_os_name', return_value='Linux')
def test_agent_elements(mock_agent_attr, mock_basic_info, mock_agents_info, mock_exists, element_type):
    """Tests every possible type of agent element

    Iterate over each element type, call the get_item_agent function with that
    parameter and verify that the response obtained contains all the expected
    fields (found in core.get_valid_fields ()).

    Parameters
    ----------
    element_type : string
        Type of element to get syscollector information from
    """
    def valid_fields_asserter(rendered_result):
        """Check that all expected keys and subkeys are in the result."""
        fields = get_valid_fields(Type(element_type))[1]
        for field in fields.keys():
            if field.__contains__('.'):
                key, subkey = field.split('.')
                results_subdict = rendered_result['data']['affected_items'][0][key]
                assert subkey in results_subdict.keys(), f'Subkey "{subkey}" not found in result'
            else:
                assert field in rendered_result['data']['affected_items'][0].keys(), f'Key "{field}" not found in result'

    with patch('fortishield.core.utils.FortishieldDBConnection') as mock_fdb:
        mock_fdb.return_value = InitWDBSocketMock(sql_schema_file='schema_syscollector_000.sql')
        results = syscollector.get_item_agent(agent_list=['000'], element_type=element_type)

        assert isinstance(results, AffectedItemsFortishieldResult)
        valid_fields_asserter(results.render())
