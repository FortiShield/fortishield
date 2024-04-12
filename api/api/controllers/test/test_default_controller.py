# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import MagicMock, patch

import pytest
from aiohttp import web_response

with patch('khulnasoft.common.fortishield_uid'):
    with patch('khulnasoft.common.fortishield_gid'):
        sys.modules['fortishield.rbac.orm'] = MagicMock()
        import fortishield.rbac.decorators
        from api.controllers.default_controller import (BasicInfo, DATE_FORMAT,
                                                        datetime, default_info,
                                                        socket)
        from fortishield.tests.util import RBAC_bypasser
        from fortishield.core.utils import get_utc_now
        fortishield.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['fortishield.rbac.orm']


@pytest.mark.asyncio
@patch('api.controllers.default_controller.load_spec', return_value=MagicMock())
@patch('api.controllers.default_controller.FortishieldResult', return_value={})
async def test_default_info(mock_wresult, mock_lspec):
    """Verify 'default_info' endpoint is working as expected."""
    result = await default_info()
    data = {
        'title': mock_lspec.return_value['info']['title'],
        'api_version': mock_lspec.return_value['info']['version'],
        'revision': mock_lspec.return_value['info']['x-revision'],
        'license_name': mock_lspec.return_value['info']['license']['name'],
        'license_url': mock_lspec.return_value['info']['license']['url'],
        'hostname': socket.gethostname(),
        'timestamp': get_utc_now().strftime(DATE_FORMAT)
    }
    mock_lspec.assert_called_once_with()
    mock_wresult.assert_called_once_with({'data': BasicInfo.from_dict(data)})
    assert isinstance(result, web_response.Response)
