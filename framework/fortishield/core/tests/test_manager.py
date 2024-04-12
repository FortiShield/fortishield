#!/usr/bin/env python
# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from datetime import timezone, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
from aiohttp import ClientError

with patch('fortishield.core.common.fortishield_uid'):
    with patch('fortishield.core.common.fortishield_gid'):
        from fortishield.core.manager import *
        from fortishield.core.exception import FortishieldException

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'manager')
ossec_log_path = '{0}/ossec_log.log'.format(test_data_path)
ossec_log_json_path = '{0}/ossec_log.log'.format(test_data_path)


class InitManager:
    def __init__(self):
        """Sets up necessary environment to test manager functions"""
        # path for temporary API files
        self.api_tmp_path = os.path.join(test_data_path, 'tmp')
        # rules
        self.input_rules_file = 'test_rules.xml'
        self.output_rules_file = 'uploaded_test_rules.xml'
        # decoders
        self.input_decoders_file = 'test_decoders.xml'
        self.output_decoders_file = 'uploaded_test_decoders.xml'
        # CDB lists
        self.input_lists_file = 'test_lists'
        self.output_lists_file = 'uploaded_test_lists'


@pytest.fixture(scope='module')
def test_manager():
    # Set up
    test_manager = InitManager()
    return test_manager


@pytest.fixture
def client_session_get_mock():
    with patch('aiohttp.ClientSession.get') as get_mock:
        yield get_mock


@pytest.fixture
def installation_uid():
    return str(uuid4())


def get_logs(json_log: bool = False):
    with open(ossec_log_json_path if json_log else ossec_log_path) as f:
        return f.read()


@pytest.mark.parametrize('process_status', [
    'running',
    'stopped',
    'failed',
    'restarting',
    'starting'
])
@patch('os.path.exists')
@patch('fortishield.core.cluster.utils.glob')
def test_get_status(manager_glob, manager_exists, test_manager, process_status):
    """Tests core.manager.status()

    Tests manager.status() function in two cases:
        * PID files are created and processed are running,
        * No process is running and therefore no PID files have been created

    Parameters
    ----------
    manager_glob : mock
        Mock of glob.glob function.
    manager_exists : mock
        Mock of os.path.exists function.
    process_status : str
        Status to test (valid values: running/stopped/failed/restarting).
    """

    def mock_glob(path_to_check):
        return [path_to_check.replace('*', '0234')] if process_status == 'running' else []

    def mock_exists(path_to_check):
        if path_to_check == '/proc/0234':
            return process_status == 'running'
        else:
            return path_to_check.endswith(f'.{process_status.replace("ing", "").replace("re", "")}') or \
                   path_to_check.endswith(f'.{process_status.replace("ing", "")}')

    manager_glob.side_effect = mock_glob
    manager_exists.side_effect = mock_exists
    manager_status = status()
    assert isinstance(manager_status, dict)
    assert all(process_status == x for x in manager_status.values())
    if process_status == 'running':
        manager_exists.assert_any_call("/proc/0234")


def test_get_ossec_log_fields():
    """Test get_ossec_log_fields() method returns a tuple"""
    result = get_ossec_log_fields('2020/07/14 06:10:40 rootcheck: INFO: Ending rootcheck scan.')
    assert isinstance(result, tuple), 'The result is not a tuple'
    assert result[0] == datetime(2020, 7, 14, 6, 10, 40, tzinfo=timezone.utc)
    assert result[1] == 'fortishield-rootcheck'
    assert result[2] == 'info'
    assert result[3] == ' Ending rootcheck scan.'


def test_get_ossec_log_fields_ko():
    """Test get_ossec_log_fields() method returns None when nothing matches """
    result = get_ossec_log_fields('DEBUG')
    assert not result


@pytest.mark.parametrize("log_format", [
    LoggingFormat.plain, LoggingFormat.json
])
def test_get_ossec_logs(log_format):
    """Test get_ossec_logs() method returns result with expected information"""
    logs = get_logs(json_log=log_format == LoggingFormat.json).splitlines()

    with patch("fortishield.core.manager.get_fortishield_active_logging_format", return_value=log_format):
        with pytest.raises(FortishieldInternalError, match=".*1020.*"):
            get_ossec_logs()

        with patch('fortishield.core.manager.exists', return_value=True):
            with patch('fortishield.core.manager.tail', return_value=logs):
                result = get_ossec_logs()
                assert all(key in log for key in ('timestamp', 'tag', 'level', 'description') for log in result)


@patch("fortishield.core.manager.get_fortishield_active_logging_format", return_value=LoggingFormat.plain)
@patch('fortishield.core.manager.exists', return_value=True)
def test_get_logs_summary(mock_exists, mock_active_logging_format):
    """Test get_logs_summary() method returns result with expected information"""
    logs = get_logs().splitlines()
    with patch('fortishield.core.manager.tail', return_value=logs):
        result = get_logs_summary()
        assert all(key in log for key in ('all', 'info', 'error', 'critical', 'warning', 'debug')
                   for log in result.values())
        assert result['fortishield-modulesd:database'] == {'all': 2, 'info': 0, 'error': 0, 'critical': 0, 'warning': 0,
                                                     'debug': 2}


@patch('fortishield.core.manager.exists', return_value=True)
@patch('fortishield.core.manager.FortishieldSocket')
def test_validate_ossec_conf(mock_fortishieldsocket, mock_exists):
    with patch('socket.socket') as sock:
        # Mock sock response
        json_response = json.dumps({'error': 0, 'message': ""}).encode()
        mock_fortishieldsocket.return_value.receive.return_value = json_response
        result = validate_ossec_conf()

        assert result == {'status': 'OK'}
        mock_exists.assert_called_with(os.path.join(common.FORTISHIELD_PATH, 'queue', 'sockets', 'com'))


@patch("fortishield.core.manager.exists", return_value=True)
def test_validation_ko(mock_exists):
    # Socket creation raise socket.error
    with patch('socket.socket', side_effect=socket.error):
        with pytest.raises(FortishieldInternalError, match='.* 1013 .*'):
            validate_ossec_conf()

    with patch('socket.socket.bind'):
        # Socket connection raise socket.error
        with patch('socket.socket.connect', side_effect=socket.error):
            with pytest.raises(FortishieldInternalError, match='.* 1013 .*'):
                validate_ossec_conf()

        # execq_socket_path not exists
        with patch("fortishield.core.manager.exists", return_value=False):
            with pytest.raises(FortishieldInternalError, match='.* 1901 .*'):
                validate_ossec_conf()

        with patch('socket.socket.connect'):
            # Socket send raise socket.error
            with patch('fortishield.core.manager.FortishieldSocket.send', side_effect=socket.error):
                with pytest.raises(FortishieldInternalError, match='.* 1014 .*'):
                    validate_ossec_conf()

            with patch('socket.socket.send'):
                # Socket recv raise socket.error
                with patch('fortishield.core.manager.FortishieldSocket.receive', side_effect=socket.timeout):
                    with pytest.raises(FortishieldInternalError, match='.* 1014 .*'):
                        validate_ossec_conf()

                # _parse_execd_output raise KeyError
                with patch('fortishield.core.manager.FortishieldSocket'):
                    with patch('fortishield.core.manager.parse_execd_output', side_effect=KeyError):
                        with pytest.raises(FortishieldInternalError, match='.* 1904 .*'):
                            validate_ossec_conf()


@pytest.mark.parametrize('error_flag, error_msg', [
    (0, ""),
    (1, "2019/02/27 11:30:07 fortishield-clusterd: ERROR: [Cluster] [Main] Error 3004 - Error in cluster configuration: "
        "Unspecified key"),
    (1, "2019/02/27 11:30:24 fortishield-authd: ERROR: (1230): Invalid element in the configuration: "
        "'use_source_i'.\n2019/02/27 11:30:24 fortishield-authd: ERROR: (1202): Configuration error at "
        "'/var/ossec/etc/ossec.conf'.")
])
def test_parse_execd_output(error_flag, error_msg):
    """Test parse_execd_output function works and returns expected message.

    Parameters
    ----------
    error_flag : int
        Indicate if there is an error found.
    error_msg
        Error message to be sent.
    """
    json_response = json.dumps({'error': error_flag, 'message': error_msg}).encode()
    if not error_flag:
        result = parse_execd_output(json_response)
        assert result['status'] == 'OK'
    else:
        with pytest.raises(FortishieldException, match=f'.* 1908 .*'):
            parse_execd_output(json_response)


@patch('fortishield.core.manager.configuration.api_conf', new={'experimental_features': True})
def test_get_api_config():
    """Checks that get_api_config method is returning current api_conf dict."""
    result = get_api_conf()
    assert result == {'experimental_features': True}


@pytest.mark.parametrize('update_check', (True, False))
@pytest.mark.parametrize('last_check_date', (None, datetime.now()))
def test_get_update_information_template(last_check_date, update_check):
    """Test that the get_update_information_template function is working properly with the given data."""

    template = get_update_information_template(update_check=update_check, last_check_date=last_check_date)

    assert 'last_check_date' in template
    assert template['last_check_date'] == (last_check_date if last_check_date is not None else '')
    assert 'update_check' in template
    assert template['update_check'] == update_check
    assert 'current_version' in template
    assert template['current_version'] == f"v{fortishield.__version__}"
    assert 'last_available_major' in template
    assert 'last_available_minor' in template
    assert 'last_available_patch' in template


@pytest.mark.asyncio
async def test_query_update_check_service_catch_exceptions_and_dont_raise(
    installation_uid, client_session_get_mock
):
    """Test that the query_update_check_service function handle errors correctly."""
    message_error = 'Some client error'
    client_session_get_mock.side_effect = ClientError(message_error)
    update_information = await query_update_check_service(installation_uid)

    client_session_get_mock.assert_called()

    assert update_information['status_code'] == 500
    assert update_information['message'] == message_error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'major,minor,patch',
    (
        [['5.0.0', '5.0.1'], ['4.9.0', '4.9.1'], ['4.8.1', '4.8.2']],
        [
            ['5.0.0', '5.0.1'],
            ['4.9.0', '4.9.1'],
            [
                '4.8.1',
            ],
        ],
        [['5.0.0', '5.0.1'], ['4.9.0'], ['4.8.1', '4.8.2']],
        [['5.0.0'], ['4.9.1'], ['4.8.1']],
        [['5.0.0'], ['4.9.1'], []],
        [['5.0.0'], [], ['4.8.1']],
        [[], ['4.9.1'], ['4.8.1']],
        [[], [], []],
    ),
)
async def test_query_update_check_service_returns_correct_data_when_status_200(
    installation_uid, client_session_get_mock, major, minor, patch
):
    """Test that query_update_check_service function proccess the updates information correctly."""
    def _build_release_info(semvers: list[str]) -> list:
        release_info = []
        for semver in semvers:
            major, minor, patch = semver.split('.')
            release_info.append(
                {
                    'tag': f'v{semver}',
                    'description': 'Some description',
                    'title': f'Fortishield {semver}',
                    'published_date': '2023-09-22T10:44:00Z',
                    'semver': {'minor': minor, 'patch': patch, 'major': major},
                }
            )

        return release_info

    response_data = {
        'data': {
            'minor': _build_release_info(minor),
            'patch': _build_release_info(patch),
            'major': _build_release_info(major),
        }
    }
    status = 200

    client_session_get_mock.return_value.__aenter__.return_value.status = status
    client_session_get_mock.return_value.__aenter__.return_value.json.return_value = (
        response_data
    )

    update_information = await query_update_check_service(installation_uid)

    client_session_get_mock.assert_called()

    assert update_information['status_code'] == status
    assert update_information['uuid'] == installation_uid

    if len(major):
        assert (
            update_information['last_available_major']
            == response_data['data']['major'][-1]
        )
    else:
        assert update_information['last_available_major'] == {}

    if len(minor):
        assert (
            update_information['last_available_minor']
            == response_data['data']['minor'][-1]
        )
    else:
        assert update_information['last_available_minor'] == {}

    if len(patch):
        assert (
            update_information['last_available_patch']
            == response_data['data']['patch'][-1]
        )
    else:
        assert update_information['last_available_patch'] == {}


async def test_query_update_check_service_returns_correct_data_on_error(
    installation_uid, client_session_get_mock
):
    """Test that query_update_check_service function returns correct data when an error occurs."""

    response_data = {'errors': {'detail': 'Unauthorized'}}
    status = 403

    client_session_get_mock.return_value.__aenter__.return_value.status = status
    client_session_get_mock.return_value.__aenter__.return_value.json.return_value = (
        response_data
    )

    update_information = await query_update_check_service(installation_uid)

    client_session_get_mock.assert_called()

    assert update_information['status_code'] == status
    assert update_information['message'] == response_data['errors']['detail']


@pytest.mark.asyncio
async def test_query_update_check_service_request(
    installation_uid, client_session_get_mock
):
    """Test that query_update_check_service function make request to the URL with the correct headers."""

    version = '4.8.0'
    with patch('framework.fortishield.core.manager.fortishield.__version__', version):
        await query_update_check_service(installation_uid)

        client_session_get_mock.assert_called()

        client_session_get_mock.assert_called_with(
            RELEASE_UPDATES_URL,
            headers={
                FORTISHIELD_UID_KEY: installation_uid,
                FORTISHIELD_TAG_KEY: f'v{version}',
            },
        )