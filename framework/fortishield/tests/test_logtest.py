# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from fortishield import FortishieldError
from fortishield.core.fortishield_socket import create_fortishield_socket_message

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

with patch('fortishield.common.fortishield_uid'):
    with patch('fortishield.common.fortishield_gid'):
        sys.modules['fortishield.rbac.orm'] = MagicMock()
        import fortishield.rbac.decorators
        from fortishield.tests.util import RBAC_bypasser

        del sys.modules['fortishield.rbac.orm']

        fortishield.rbac.decorators.expose_resources = RBAC_bypasser

        from fortishield.logtest import run_logtest, end_logtest_session


def send_logtest_msg_mock(**kwargs):
    socket_response = create_fortishield_socket_message(command=kwargs['command'], parameters=kwargs['parameters'])
    socket_response['error'] = 0
    return socket_response


@pytest.mark.parametrize('logtest_param_values', [
    [None, 'event_value', 'log_format_value', 'location_value'],
    ['token_value', 'event_value', 'log_format_value', 'location_value'],
])
def test_get_logtest_output(logtest_param_values):
    """Test `run_logtest` function from module logtest.

    Parameters
    ----------
    logtest_param_values : list of str
        List of values for every kwarg.
    """
    kwargs_keys = ['token', 'event', 'log_format', 'location']
    kwargs = {key: value for key, value in zip(kwargs_keys, logtest_param_values)}
    with patch('fortishield.logtest.send_logtest_msg') as send_mock:
        send_mock.side_effect = send_logtest_msg_mock
        result = run_logtest(**kwargs)
        assert result
        # Remove error field. It was mocked
        del result['error']

        assert result['command'] == 'log_processing'
        assert result['parameters'].items() <= kwargs.items()


def test_get_logtest_output_ko():
    """Test `run_logtest` exceptions."""
    with patch('fortishield.logtest.send_logtest_msg') as send_mock:
        send_mock.return_value = {'error': 1}
        try:
            run_logtest()
        except FortishieldError as e:
            assert e.code == 7000


@pytest.mark.parametrize('token', [
    'thisisarandomtoken123',
    'anotherrandomtoken321'
])
def test_end_logtest_session(token):
    """Test `end_logtest_session_ko` function from module logtest.

    Parameters
    ----------
    token : str
        Logtest session token.
    """
    with patch('fortishield.logtest.send_logtest_msg') as send_mock:
        send_mock.side_effect = send_logtest_msg_mock
        result = end_logtest_session(token=token)
        assert result['command'] == 'remove_session'
        assert result['parameters'] == {'token': token}


def test_end_logtest_session_ko():
    """Test `end_logtest_session_ko` exceptions."""
    with patch('fortishield.logtest.send_logtest_msg') as send_mock:
        send_mock.return_value = {'error': 1}
        try:
            end_logtest_session(token='whatever')
        except FortishieldError as e:
            assert e.code == 7000

    try:
        end_logtest_session()
    except FortishieldError as e:
        assert e.code == 7001
