# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, MagicMock, call
from asyncio import BaseEventLoop, BaseProtocol, StreamWriter, StreamReader, BaseTransport
from struct import pack

import pytest
from fortishield.core.exception import FortishieldException
from fortishield.core.fortishield_socket import FortishieldSocket, FortishieldSocketJSON, \
     SOCKET_COMMUNICATION_PROTOCOL_VERSION, create_fortishield_socket_message, FortishieldAsyncSocket, \
     FortishieldAsyncSocketJSON

@pytest.fixture
def oux_conn_patch():
    """Fixture with asyncio.open_unix_connection patched."""
    return patch('asyncio.open_unix_connection',
                 return_value=(StreamReader(),StreamWriter(protocol=BaseProtocol(),
                                                           transport=BaseTransport(),
                                                           loop=BaseEventLoop(),
                                                           reader=None)))

@pytest.mark.asyncio
@pytest.fixture
async def connected_fortishield_async_socket(oux_conn_patch):
    """Fixture to instantiate FortishieldAsyncSocket."""
    with oux_conn_patch:
        s = FortishieldAsyncSocket()
        await s.connect('/any/pipe')
        yield s


@patch('fortishield.core.fortishield_socket.FortishieldSocket._connect')
def test_FortishieldSocket__init__(mock_conn):
    """Tests FortishieldSocket.__init__ function works"""

    FortishieldSocket('test_path')

    mock_conn.assert_called_once_with()


@patch('fortishield.core.fortishield_socket.socket.socket.connect')
def test_FortishieldSocket_protected_connect(mock_conn):
    """Tests FortishieldSocket._connect function works"""

    FortishieldSocket('test_path')

    mock_conn.assert_called_with('test_path')


@patch('fortishield.core.fortishield_socket.socket.socket.connect', side_effect=Exception)
def test_FortishieldSocket_protected_connect_ko(mock_conn):
    """Tests FortishieldSocket._connect function exceptions works"""

    with pytest.raises(FortishieldException, match=".* 1013 .*"):
        FortishieldSocket('test_path')


@patch('fortishield.core.fortishield_socket.socket.socket.connect')
@patch('fortishield.core.fortishield_socket.socket.socket.close')
def test_FortishieldSocket_close(mock_close, mock_conn):
    """Tests FortishieldSocket.close function works"""

    queue = FortishieldSocket('test_path')

    queue.close()

    mock_conn.assert_called_once_with('test_path')
    mock_close.assert_called_once_with()


@patch('fortishield.core.fortishield_socket.socket.socket.connect')
@patch('fortishield.core.fortishield_socket.socket.socket.send')
def test_FortishieldSocket_send(mock_send, mock_conn):
    """Tests FortishieldSocket.send function works"""

    queue = FortishieldSocket('test_path')

    response = queue.send(b"\x00\x01")

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('msg, effect, send_effect, expected_exception', [
    ('text_msg', 'side_effect', None, 1105),
    (b"\x00\x01", 'return_value', 0, 1014),
    (b"\x00\x01", 'side_effect', Exception, 1014)
])
@patch('fortishield.core.fortishield_socket.socket.socket.connect')
def test_FortishieldSocket_send_ko(mock_conn, msg, effect, send_effect, expected_exception):
    """Tests FortishieldSocket.send function exceptions works"""

    queue = FortishieldSocket('test_path')

    if effect == 'return_value':
        with patch('fortishield.core.fortishield_socket.socket.socket.send', return_value=send_effect):
            with pytest.raises(FortishieldException, match=f'.* {expected_exception} .*'):
                queue.send(msg)
    else:
        with patch('fortishield.core.fortishield_socket.socket.socket.send', side_effect=send_effect):
            with pytest.raises(FortishieldException, match=f'.* {expected_exception} .*'):
                queue.send(msg)

    mock_conn.assert_called_once_with('test_path')


@patch('fortishield.core.fortishield_socket.socket.socket.connect')
@patch('fortishield.core.fortishield_socket.unpack', return_value='1024')
@patch('fortishield.core.fortishield_socket.socket.socket.recv')
def test_FortishieldSocket_receive(mock_recv, mock_unpack, mock_conn):
    """Tests FortishieldSocket.receive function works"""

    queue = FortishieldSocket('test_path')

    response = queue.receive()

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@patch('fortishield.core.fortishield_socket.socket.socket.connect')
@patch('fortishield.core.fortishield_socket.socket.socket.recv', side_effect=Exception)
def test_FortishieldSocket_receive_ko(mock_recv, mock_conn):
    """Tests FortishieldSocket.receive function exception works"""

    queue = FortishieldSocket('test_path')

    with pytest.raises(FortishieldException, match=".* 1014 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')


@patch('fortishield.core.fortishield_socket.FortishieldSocket._connect')
def test_FortishieldSocketJSON__init__(mock_conn):
    """Tests FortishieldSocketJSON.__init__ function works"""

    FortishieldSocketJSON('test_path')

    mock_conn.assert_called_once_with()


@patch('fortishield.core.fortishield_socket.socket.socket.connect')
@patch('fortishield.core.fortishield_socket.FortishieldSocket.send')
def test_FortishieldSocketJSON_send(mock_send, mock_conn):
    """Tests FortishieldSocketJSON.send function works"""

    queue = FortishieldSocketJSON('test_path')

    response = queue.send('test_msg')

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('raw', [
    True, False
])
@patch('fortishield.core.fortishield_socket.socket.socket.connect')
@patch('fortishield.core.fortishield_socket.FortishieldSocket.receive')
@patch('fortishield.core.fortishield_socket.loads', return_value={'error':0, 'message':None, 'data':'Ok'})
def test_FortishieldSocketJSON_receive(mock_loads, mock_receive, mock_conn, raw):
    """Tests FortishieldSocketJSON.receive function works"""
    queue = FortishieldSocketJSON('test_path')
    response = queue.receive(raw=raw)
    if raw:
        assert isinstance(response, dict)
    else:
        assert isinstance(response, str)
    mock_conn.assert_called_once_with('test_path')


@patch('fortishield.core.fortishield_socket.socket.socket.connect')
@patch('fortishield.core.fortishield_socket.FortishieldSocket.receive')
@patch('fortishield.core.fortishield_socket.loads', return_value={'error':10000, 'message':'Error', 'data':'KO'})
def test_FortishieldSocketJSON_receive_ko(mock_loads, mock_receive, mock_conn):
    """Tests FortishieldSocketJSON.receive function works"""

    queue = FortishieldSocketJSON('test_path')

    with pytest.raises(FortishieldException, match=".* 10000 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('origin, command, parameters', [
    ('origin_sample', 'command_sample', {'sample': 'sample'}),
    (None, 'command_sample', {'sample': 'sample'}),
    ('origin_sample', None, {'sample': 'sample'}),
    ('origin_sample', 'command_sample', None),
    (None, None, None)
])
def test_create_fortishield_socket_message(origin, command, parameters):
    """Test create_fortishield_socket_message function."""
    response_message = create_fortishield_socket_message(origin, command, parameters)
    assert response_message['version'] == SOCKET_COMMUNICATION_PROTOCOL_VERSION
    assert response_message.get('origin') == origin
    assert response_message.get('command') == command
    assert response_message.get('parameters') == parameters


@pytest.mark.asyncio
async def test_fortishield_async_socket_connect():
    """Test socket connection."""
    s = FortishieldAsyncSocket()
    with patch('asyncio.open_unix_connection', 
               return_value=(StreamReader(),
                             StreamWriter(protocol=BaseProtocol(),
                                          transport=BaseTransport(),
                                          loop=BaseEventLoop(),
                                          reader=StreamReader()))) as mock_open:
        await s.connect(path_to_socket='/etc/socket/path')
        assert isinstance(s.reader, StreamReader, )
        assert isinstance(s.writer, StreamWriter)
        mock_open.assert_awaited_once_with('/etc/socket/path')


@pytest.mark.parametrize('exception', [(ValueError()),(OSError),(FileNotFoundError),((AttributeError()))])
async def test_fortishield_async_socket_connect_ko(exception):
    """Test socket connection errors."""
    s = FortishieldAsyncSocket()
    oux_conn_patch.side_effect = exception
    with patch('asyncio.open_unix_connection', side_effect=exception):
        with pytest.raises(FortishieldException) as exc_info:
            await s.connect(path_to_socket='/etc/socket/path')

    assert exc_info.value.code == 1013
    assert exc_info.errisinstance(FortishieldException)


@pytest.mark.asyncio
async def test_fortishield_async_socket_receive(connected_fortishield_async_socket: FortishieldAsyncSocket):
    """Test receive function."""
    with patch.object(connected_fortishield_async_socket.reader, 'read',
                      side_effect=[b'\x05\x00\x00\x00', b'12345']) as read_patch:
        data = await connected_fortishield_async_socket.receive()
        assert data == b'12345'
        read_patch.assert_has_awaits([call(4), call(5)])


@pytest.mark.asyncio
async def test_fortishield_async_socket_receive_ko(connected_fortishield_async_socket: FortishieldAsyncSocket):
    """Test receive function."""
    with patch.object(connected_fortishield_async_socket.reader, 'read',
                      side_effect=Exception()):
        with pytest.raises(FortishieldException) as exc_info:
            await connected_fortishield_async_socket.receive()
    assert exc_info.value.code == 1014
    assert exc_info.errisinstance(FortishieldException)


@pytest.mark.asyncio
async def test_fortishield_async_socket_send(connected_fortishield_async_socket: FortishieldAsyncSocket):
    """Test receive function."""
    d_bytes = b'12345'
    with patch.object(connected_fortishield_async_socket.writer, 'write') as write_patch,\
         patch.object(connected_fortishield_async_socket.writer, 'drain') as drain_patch:
        await connected_fortishield_async_socket.send(d_bytes)
        bytes_sent = pack('<I', len(d_bytes)) + d_bytes
        write_patch.assert_called_once_with(bytes_sent)
        drain_patch.assert_awaited_once()


@pytest.mark.asyncio
async def test_fortishield_async_socket_send_ko(connected_fortishield_async_socket: FortishieldAsyncSocket):
    """Test receive function."""
    with patch.object(connected_fortishield_async_socket.writer, 'write',
                      side_effect=OSError()):
        with pytest.raises(FortishieldException) as exc_info:
            await connected_fortishield_async_socket.send(b'12345')
    assert exc_info.value.code == 1014
    assert exc_info.errisinstance(FortishieldException)


def test_fortishield_async_socket_close(connected_fortishield_async_socket: FortishieldAsyncSocket):
    """Test receive function."""

    with patch.object(connected_fortishield_async_socket.writer, 'close') as close_patch:
        connected_fortishield_async_socket.close()
        close_patch.assert_called_once()


@pytest.mark.asyncio
async def test_fortishield_async_json_socket_receive_json():
    """Test receive_json function."""

    s = FortishieldAsyncSocketJSON()
    with patch.object(FortishieldAsyncSocket,
                      'receive', return_value=b'{"data": {"field":"value"}}') as receive_patch:
        msg = await s.receive_json()
        receive_patch.assert_called_once()
        assert msg['field'] == 'value'


@pytest.mark.asyncio
async def test_fortishield_async_json_socket_receive_json_ko():
    """Test receive_json function."""

    s = FortishieldAsyncSocketJSON()
    with patch.object(FortishieldAsyncSocket, 'receive',
                      return_value=b'{"error": 1000, "message": "error message"}'):
        with pytest.raises(FortishieldException) as exc_info:
            await s.receive_json()
        exc_info.errisinstance(FortishieldException)
        assert exc_info.value.code == 1000
