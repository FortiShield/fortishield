# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from aiohttp import web_response
from api.controllers.test.utils import CustomAffectedItems

with patch('khulnasoft.common.fortishield_uid'):
    with patch('khulnasoft.common.fortishield_gid'):
        sys.modules['fortishield.rbac.orm'] = MagicMock()
        import fortishield.rbac.decorators
        from api.controllers.syscheck_controller import (delete_syscheck_agent,
                                                         get_last_scan_agent,
                                                         get_syscheck_agent,
                                                         put_syscheck)
        from fortishield import syscheck
        from fortishield.tests.util import RBAC_bypasser
        fortishield.rbac.decorators.expose_resources = RBAC_bypasser        
        del sys.modules['fortishield.rbac.orm']


@pytest.mark.asyncio
@patch('api.controllers.syscheck_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.syscheck_controller.remove_nones_to_dict')
@patch('api.controllers.syscheck_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.syscheck_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_syscheck(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'put_syscheck' endpoint is working as expected."""
    result = await put_syscheck(request=mock_request)
    f_kwargs = {'agent_list': '*'
                }
    mock_dapi.assert_called_once_with(f=syscheck.run,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      broadcasting=True,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.syscheck_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.syscheck_controller.remove_nones_to_dict')
@patch('api.controllers.syscheck_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.syscheck_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_syscheck_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_syscheck_agent' endpoint is working as expected."""
    result = await get_syscheck_agent(request=mock_request,
                                      agent_id='001')
    type_ = mock_request.query.get('type', None)
    hash_ = mock_request.query.get('hash', None)
    file_ = mock_request.query.get('file', None)
    filters = {'type': type_,
               'md5': None,
               'sha1': None,
               'sha256': None,
               'hash': hash_,
               'file': file_,
               'arch': None,
               'value.name': mock_request.query.get('value.name', None),
               'value.type': mock_request.query.get('value.type', None)
               }
    f_kwargs = {'agent_list': ['001'],
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'summary': False,
                'filters': filters,
                'distinct': False,
                'q': None
                }
    mock_dapi.assert_called_once_with(f=syscheck.files,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.syscheck_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.syscheck_controller.remove_nones_to_dict')
@patch('api.controllers.syscheck_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.syscheck_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_delete_syscheck_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'delete_syscheck_agent' endpoint is working as expected."""
    result = await delete_syscheck_agent(request=mock_request)
    f_kwargs = {'agent_list': ['*']
                }
    mock_dapi.assert_called_once_with(f=syscheck.clear,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.syscheck_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.syscheck_controller.remove_nones_to_dict')
@patch('api.controllers.syscheck_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.syscheck_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_last_scan_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_last_scan_agent' endpoint is working as expected."""
    result = await get_last_scan_agent(request=mock_request,
                                       agent_id='001')
    f_kwargs = {'agent_list': ['001']
                }
    mock_dapi.assert_called_once_with(f=syscheck.last_scan,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, web_response.Response)
