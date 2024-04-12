# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from datetime import date
from json import dumps
from unittest.mock import call, MagicMock, patch

import pytest

with patch('fortishield.core.common.fortishield_uid'):
    with patch('fortishield.core.common.fortishield_gid'):
        sys.modules['fortishield.rbac.orm'] = MagicMock()
        import fortishield.rbac.decorators
        from fortishield.tests.util import RBAC_bypasser

        del sys.modules['fortishield.rbac.orm']
        fortishield.rbac.decorators.expose_resources = RBAC_bypasser

        import fortishield.stats as stats
        from fortishield.core.results import AffectedItemsFortishieldResult
        from api.util import remove_nones_to_dict
        from fortishield.core.tests.test_agent import InitAgent

SOCKET_PATH_DAEMONS_MAPPING = {'/var/ossec/queue/sockets/remote': 'fortishield-remoted',
                               '/var/ossec/queue/sockets/analysis': 'fortishield-analysisd'}
DAEMON_SOCKET_PATHS_MAPPING = {'fortishield-remoted': '/var/ossec/queue/sockets/remote',
                               'fortishield-analysisd': '/var/ossec/queue/sockets/analysis'}

test_data = InitAgent()


def send_msg_to_fdb(msg, raw=False):
    query = ' '.join(msg.split(' ')[2:])
    result = list(map(remove_nones_to_dict, map(dict, test_data.cur.execute(query).fetchall())))
    return ['ok', dumps(result)] if raw else result


def test_totals():
    """Verify totals() function works and returns correct data"""
    with patch('fortishield.stats.totals_', return_value=({})):
        response = stats.totals(date(2019, 8, 13))
        assert response.total_affected_items == len(response.affected_items)
        assert isinstance(response, AffectedItemsFortishieldResult), 'The result is not FortishieldResult type'


def test_hourly():
    """Makes sure hourly() fit with the expected."""
    response = stats.hourly()
    assert isinstance(response, AffectedItemsFortishieldResult), 'The result is not FortishieldResult type'
    assert response.total_affected_items == len(response.affected_items)


def test_weekly():
    """Makes sure weekly() fit with the expected."""
    response = stats.weekly()
    assert isinstance(response, AffectedItemsFortishieldResult), 'The result is not FortishieldResult type'
    assert response.total_affected_items == len(response.affected_items)


@pytest.mark.asyncio
@patch('fortishield.core.common.REMOTED_SOCKET', '/var/ossec/queue/sockets/remote')
@patch('fortishield.core.common.ANALYSISD_SOCKET', '/var/ossec/queue/sockets/analysis')
@patch('fortishield.core.common.WDB_SOCKET', '/var/ossec/queue/db/fdb')
@patch('fortishield.stats.get_daemons_stats_socket')
async def test_get_daemons_stats(mock_get_daemons_stats_socket):
    """Makes sure get_daemons_stats() fit with the expected."""
    response = await stats.get_daemons_stats(['fortishield-remoted', 'fortishield-analysisd', 'fortishield-db'])

    calls = [call('/var/ossec/queue/sockets/remote'), call('/var/ossec/queue/sockets/analysis'),
             call('/var/ossec/queue/db/fdb')]
    mock_get_daemons_stats_socket.assert_has_calls(calls)
    assert isinstance(response, AffectedItemsFortishieldResult), \
            'The result is not AffectedItemsFortishieldResult type'
    assert response.total_affected_items == len(response.affected_items)


@pytest.mark.asyncio
@patch('fortishield.core.common.REMOTED_SOCKET', '/var/ossec/queue/sockets/wrong_socket_name')
async def test_get_daemons_stats_ko():
    """Makes sure get_daemons_stats() fit with the expected."""
    response = await stats.get_daemons_stats(['fortishield-remoted'])

    assert isinstance(response, AffectedItemsFortishieldResult), \
        'The result is not AffectedItemsFortishieldResult type'

    assert response.render()['data']['failed_items'][0]['error']['code'] == 1121, \
        'Expected error code was not returned'


def side_effect_test_get_daemons_stats(daemon_path, agents_list):
    return {'name': SOCKET_PATH_DAEMONS_MAPPING[daemon_path], 'agents': [{'id': a} for a in agents_list]}


@pytest.mark.asyncio
@pytest.mark.parametrize('daemons_list, expected_daemons_list', [
    ([], ['fortishield-remoted', 'fortishield-analysisd']),
    (['fortishield-remoted'], ['fortishield-remoted']),
    (['fortishield-remoted', 'fortishield-analysisd'], ['fortishield-remoted', 'fortishield-analysisd'])
])
@patch('fortishield.core.fdb.FortishieldDBConnection._send', side_effect=send_msg_to_fdb)
@patch('socket.socket.connect')
@patch('fortishield.stats.get_agents_info', return_value={'000', '001', '002', '003', '004', '005'})
@patch('fortishield.core.common.REMOTED_SOCKET', '/var/ossec/queue/sockets/remote')
@patch('fortishield.core.common.ANALYSISD_SOCKET', '/var/ossec/queue/sockets/analysis')
@patch('fortishield.stats.get_daemons_stats_socket', side_effect=side_effect_test_get_daemons_stats)
async def test_get_daemons_stats_agents(mock_get_daemons_stats_socket, mock_get_agents_info, 
                                        mock_socket_connect, mock_send_fdb, 
                                        daemons_list, expected_daemons_list):
    """Makes sure get_daemons_stats_agents() fit with the expected."""
    agents_list = ['000', '001', '004', '999']  # Only stats from 001 are obtained
    expected_errors_and_items = {'1703': {'000'}, '1701': {'999'}, '1707': {'004'}}
    result = await stats.get_daemons_stats_agents(daemons_list, agents_list)

    # get_daemons_stats_socket called with the expected parameters
    calls = [call(DAEMON_SOCKET_PATHS_MAPPING[daemon], agents_list=[1])
             for daemon in expected_daemons_list]
    mock_get_daemons_stats_socket.assert_has_calls(calls)

    # Check affected_items
    assert result.affected_items == [{'name': daemon, 'agents': [{'id': 1}]}
                                     for daemon in expected_daemons_list]
    assert result.total_affected_items == len(expected_daemons_list)

    # Check failed items
    error_codes_in_failed_items = [error.code for error in result.failed_items.keys()]
    failed_items = list(result.failed_items.values())
    errors_and_items = {str(error): failed_items[i]
                        for i, error in enumerate(error_codes_in_failed_items)}
    assert expected_errors_and_items == errors_and_items

    assert isinstance(result, AffectedItemsFortishieldResult), \
        'The result is not an AffectedItemsFortishieldResult object'


def side_effect_test_get_daemons_stats_all(daemon_path, agents_list, last_id):
    # side_effect used to return a response with 10 items and 'due' the first time that get_daemons_stats_socket is
    # called, and a response with 10 items and 'ok' the second time
    if last_id:
        last_id += 1
    return {'data': {'name': SOCKET_PATH_DAEMONS_MAPPING[daemon_path],
                     'agents': [{'id': i} for i in range(last_id, last_id + 10)]},
            'message': 'due' if last_id == 0 else 'ok',
            'error': 1 if last_id == 0 else 0}


@pytest.mark.asyncio
@pytest.mark.parametrize('daemons_list, expected_daemons_list', [
    ([], ['fortishield-remoted', 'fortishield-analysisd']),
    (['fortishield-remoted'], ['fortishield-remoted']),
    (['fortishield-remoted', 'fortishield-analysisd'], ['fortishield-remoted', 'fortishield-analysisd'])
])
@patch('fortishield.core.common.REMOTED_SOCKET', '/var/ossec/queue/sockets/remote')
@patch('fortishield.core.common.ANALYSISD_SOCKET', '/var/ossec/queue/sockets/analysis')
@patch('fortishield.stats.get_daemons_stats_socket', side_effect=side_effect_test_get_daemons_stats_all)
async def test_get_daemons_stats_all_agents(mock_get_daemons_stats_socket, 
                                            daemons_list, expected_daemons_list):
    """Makes sure get_daemons_stats_agents() fit with the expected."""
    result = await stats.get_daemons_stats_agents(daemons_list, ['all'])

    # get_daemons_stats_socket called with the expected parameters
    calls = []
    for daemon in expected_daemons_list:
        calls.extend((call(DAEMON_SOCKET_PATHS_MAPPING[daemon], agents_list='all', last_id=0),
                      call(DAEMON_SOCKET_PATHS_MAPPING[daemon], agents_list='all', last_id=9)))
    mock_get_daemons_stats_socket.assert_has_calls(calls)

    # Check affected_items
    expected_affected_items = [{'name': daemon, 'agents': [{'id': i} for i in range(0, 20)]}
                               for daemon in expected_daemons_list]
    assert result.affected_items == expected_affected_items
    assert result.total_affected_items == len(expected_daemons_list)

    # Check failed items
    assert not result.failed_items

    assert isinstance(result, AffectedItemsFortishieldResult), \
        'The result is not an AffectedItemsFortishieldResult object'


@patch('fortishield.stats.get_daemons_stats_', return_value=[{"events_decoded": 1.0}])
def test_deprecated_get_daemons_stats(mock_daemons_stats_):
    """Makes sure deprecated_get_daemons_stats() fit with the expected."""
    response = stats.deprecated_get_daemons_stats('filename')
    assert isinstance(response, AffectedItemsFortishieldResult), 'The result is not FortishieldResult type'
    assert response.total_affected_items == len(response.affected_items)


@pytest.mark.parametrize('component', [
    'logcollector', 'test'
])
@patch('fortishield.core.agent.Agent.get_stats')
@patch('fortishield.stats.get_agents_info', return_value=['000', '001'])
def test_get_agents_component_stats_json(mock_agents_info, mock_getstats, component):
    """Test `get_agents_component_stats_json` function from agent module."""
    response = stats.get_agents_component_stats_json(agent_list=['001'], component=component)
    assert isinstance(response, AffectedItemsFortishieldResult), 'The result is not AffectedItemsFortishieldResult type'
    mock_getstats.assert_called_once_with(component=component)


@patch('fortishield.core.agent.Agent.get_stats')
@patch('fortishield.stats.get_agents_info', return_value=['000', '001'])
def test_get_agents_component_stats_json_ko(mock_agents_info, mock_getstats):
    """Test `get_agents_component_stats_json` function from agent module."""
    response = stats.get_agents_component_stats_json(agent_list=['003'], component='logcollector')
    assert isinstance(response, AffectedItemsFortishieldResult), 'The result is not AffectedItemsFortishieldResult type'
    assert response.render()['data']['failed_items'][0]['error']['code'] == 1701, 'Expected error code was not returned'
