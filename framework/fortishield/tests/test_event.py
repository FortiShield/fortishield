# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import MagicMock, patch
from fortishield.core.exception import FortishieldError


import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

with patch('fortishield.core.common.fortishield_uid'):
    with patch('fortishield.core.common.fortishield_gid'):
        sys.modules['fortishield.rbac.orm'] = MagicMock()
        import fortishield.rbac.decorators
        from fortishield.tests.util import RBAC_bypasser

        del sys.modules['fortishield.rbac.orm']
        fortishield.rbac.decorators.expose_resources = RBAC_bypasser

        from fortishield.event import MSG_HEADER, send_event_to_analysisd


@pytest.mark.parametrize('events,side_effects,message', [
    (['{"foo": 1}'], (None,), 'All events were forwarded to analisysd'),
    (['{"foo": 1}', '{"bar": 2}'], (None, None), 'All events were forwarded to analisysd'),
    (['{"foo": 1}', '{"bar": 2}'], (FortishieldError(1014), None), 'Some events were forwarded to analisysd'),
    (['{"foo": 1}', '{"bar": 2}'], (FortishieldError(1014), FortishieldError(1014)), 'No events were forwarded to analisysd'),
])
@patch('fortishield.event.FortishieldAnalysisdQueue.send_msg')
@patch('socket.socket.connect')
def test_send_event_to_analysisd(socket_mock, send_msg_mock, events, side_effects, message):
    send_msg_mock.side_effect = side_effects
    ret_val = send_event_to_analysisd(events=events)

    assert send_msg_mock.call_count == len(events)
    for i, event in enumerate(events):
        assert send_msg_mock.call_args_list[i].kwargs['msg_header'] == MSG_HEADER
        assert send_msg_mock.call_args_list[i].kwargs['msg'] == event

    assert ret_val.affected_items == [events[i] for i, v in enumerate(side_effects) if v is None]
    assert ret_val.message == message
