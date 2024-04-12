# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest


with patch('fortishield.core.common.fortishield_uid'):
    with patch('fortishield.core.common.fortishield_gid'):
        from fortishield.core.task import *
        from fortishield.core.utils import FortishieldDBQuery


def test_fortishield_db_query_task__init__():
    """Check if FortishieldDBQueryTask is properly initialized."""
    with patch('fortishield.core.utils.FortishieldDBQuery.__init__') as mock_fdbq, \
            patch('fortishield.core.utils.FortishieldDBBackend.__init__', return_value=None) as mock_fdb_backend:
        FortishieldDBQueryTask()
        mock_fdbq.assert_called_once()
        mock_fdb_backend.assert_called_with(query_format='task')


@patch('fortishield.core.fortishield_socket.FortishieldSocket._connect')
@patch('fortishield.core.fortishield_socket.FortishieldSocket.receive', return_value=b'"{\'test\':\'test\'}"')
@patch('fortishield.core.fortishield_socket.FortishieldSocket.send')
@patch('fortishield.core.fortishield_socket.FortishieldSocket.close')
def test_send_to_tasks_socket(mock_close, mock_send, mock_receive, mock_connect):
    """Check if the function send_to_tasks_socket works properly.

    Parameters
    ----------
        mock_send: MagicMock
            Mock of FortishieldSocket's method send.
        mock_connect: MagicMock
            Mock of FortishieldSocket's method connect.
        mock_close: MagicMock
            Mock of FortishieldSocket's method close.
        mock_receive: MagicMock
            Mock of FortishieldSocket's method receive.
    """
    command = {'test': 'test'}
    send_to_tasks_socket(command)
    mock_send.assert_called_with(b'{"test": "test"}')
    mock_close.assert_called_once()


def test_send_to_tasks_socket_ko():
    """Check if the function send_to_tasks_socket raises an exception when there's an error with the socket."""
    with pytest.raises(FortishieldInternalError, match=".* 1121 .*"):
        send_to_tasks_socket({'test': 'test'})


def test_fortishield_db_query_task__final_query():
    """Check if FortishieldDBQueryTask's method _final_query works properly."""
    with patch('fortishield.core.utils.FortishieldDBBackend.__init__', return_value=None), \
            patch('fortishield.core.utils.FortishieldDBQuery._default_query', return_value='test'):
        fdbq_task = FortishieldDBQueryTask()
        assert fdbq_task._final_query() == f'test WHERE task_id IN (test) LIMIT :limit OFFSET :offset'


def test_fortishield_db_query_task__format_data_into_dictionary():
    """Check that FortishieldDBQueryTask's method _format_data_into_dictionary works properly."""
    data = [
        {'task_id': 1, 'agent_id': '002', 'node': 'worker1', 'module': 'upgrade_module', 'command': 'upgrade',
         'create_time': 1606466932, 'last_update_time': 1606466953, 'status': 'Legacy', 'error_message': None}
    ]

    with patch('fortishield.core.utils.FortishieldDBBackend.__init__', return_value=None), \
            patch('fortishield.core.utils.FortishieldDBQuery._default_query', return_value='test'):
        fdbq_task = FortishieldDBQueryTask()

    fdbq_task._data = data
    result = fdbq_task._format_data_into_dictionary()

    assert result['items'][0]['task_id'] == 1
    assert result['items'][0]['agent_id'] == '002'
    assert result['items'][0]['node'] == 'worker1'
    assert result['items'][0]['module'] == 'upgrade_module'
    assert result['items'][0]['command'] == 'upgrade'
    assert result['items'][0]['create_time'] == '2020-11-27T08:48:52Z'
    assert result['items'][0]['last_update_time'] == '2020-11-27T08:49:13Z'
    assert result['items'][0]['status'] == 'Legacy'
    assert result['items'][0]['error_message'] == None


@pytest.mark.parametrize('field_name, field_filter, q_filter', [
    ('agent_list', 'field', {'value': '1', 'operator': 'LIKE'}),
    ('task_list', 'test', {'value': '1', 'operator': 'LIKE'}),
    ('test_field', 'test', {'value': '1', 'operator': 'LIKE'})
])
def test_fortishield_db_query_task__process_filter(field_name, field_filter, q_filter):
    """Check that FortishieldDBQueryTask's method _process_filter works properly."""
    with patch('fortishield.core.utils.FortishieldDBBackend.__init__', return_value=None), \
            patch('fortishield.core.utils.FortishieldDBQuery._default_query', return_value='test'):
        fdbq_task = FortishieldDBQueryTask()

    with patch.object(FortishieldDBQuery, '_process_filter') as mock_sup_proc:
        fdbq_task._process_filter(field_name, field_filter, q_filter)
        if field_name == 'agent_list':
            assert f'agent_id {q_filter["operator"]} (:{field_filter})' in fdbq_task.query
            assert fdbq_task.request[field_filter] == q_filter['value']
        elif field_name == 'task_list':
            assert f'task_id {q_filter["operator"]} (:{field_filter})' in fdbq_task.query
            assert fdbq_task.request[field_filter] == q_filter['value']
        else:
            mock_sup_proc.assert_called()
