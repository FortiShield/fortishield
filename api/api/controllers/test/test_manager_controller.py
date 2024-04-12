# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from aiohttp import web_response
from api.constants import INSTALLATION_UID_KEY, UPDATE_INFORMATION_KEY
from api.controllers.test.utils import CustomAffectedItems
from connexion.lifecycle import ConnexionResponse

with patch('khulnasoft.common.fortishield_uid'):
    with patch('khulnasoft.common.fortishield_gid'):
        sys.modules['fortishield.rbac.orm'] = MagicMock()
        import fortishield.rbac.decorators
        import fortishield.stats as stats
        from api.controllers.manager_controller import (
            check_available_version, get_api_config, get_conf_validation, get_configuration, get_info,
            get_log, get_log_summary, get_manager_config_ondemand, get_stats,
            get_stats_analysisd, get_stats_hourly, get_stats_remoted, get_daemon_stats,
            get_stats_weekly, get_status, put_restart, update_configuration)
        from fortishield import manager
        from fortishield.core import common
        from fortishield.core.manager import query_update_check_service
        from fortishield.tests.util import RBAC_bypasser

        fortishield.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['fortishield.rbac.orm']


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_status(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_status' endpoint is working as expected."""
    result = await get_status(request=mock_request)
    mock_dapi.assert_called_once_with(f=manager.get_status,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_info(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_info' endpoint is working as expected."""
    result = await get_info(request=mock_request)
    mock_dapi.assert_called_once_with(f=manager.get_basic_info,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_bool', [True, False])
async def test_get_configuration(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_bool, mock_request=MagicMock()):
    """Verify 'get_configuration' endpoint is working as expected."""
    with patch('api.controllers.manager_controller.isinstance', return_value=mock_bool) as mock_isinstance:
        result = await get_configuration(request=mock_request)
        f_kwargs = {'section': None,
                    'field': None,
                    'raw': False,
                    'distinct': False,
                    }
        mock_dapi.assert_called_once_with(f=manager.read_ossec_conf,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='local_any',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies']
                                          )
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        mock_remove.assert_called_once_with(f_kwargs)
        if mock_isinstance.return_value:
            assert isinstance(result, web_response.Response)
        else:
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_daemon_stats_node(mock_exc, mock_dapi, mock_remove, mock_dfunc):
    """Verify 'get_daemon_stats_node' function is working as expected."""
    mock_request = MagicMock()
    result = await get_daemon_stats(request=mock_request, daemons_list=['daemon_1', 'daemon_2'])

    f_kwargs = {'daemons_list': ['daemon_1', 'daemon_2']}
    mock_dapi.assert_called_once_with(f=stats.get_daemons_stats,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=True,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies'])
    mock_remove.assert_called_once_with(f_kwargs)
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_date', [None, 'date_value'])
async def test_get_stats(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_date, mock_request=MagicMock()):
    """Verify 'get_stats' endpoint is working as expected."""
    with patch('api.controllers.manager_controller.deserialize_date', return_value='desdate_value') as mock_desdate:
        result = await get_stats(request=mock_request,
                                 date=mock_date)
        if not mock_date:
            f_kwargs = {'date': ANY
                        }
        else:
            mock_desdate.assert_called_once_with(mock_date)
            f_kwargs = {'date': mock_desdate.return_value
                        }
        mock_dapi.assert_called_once_with(f=stats.totals,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='local_any',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies']
                                          )
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_stats_hourly(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_stats_hourly' endpoint is working as expected."""
    result = await get_stats_hourly(request=mock_request)
    mock_dapi.assert_called_once_with(f=stats.hourly,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_stats_weekly(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_stats_weekly' endpoint is working as expected."""
    result = await get_stats_weekly(request=mock_request)
    mock_dapi.assert_called_once_with(f=stats.weekly,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_stats_analysisd(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_stats_analysisd' endpoint is working as expected."""
    result = await get_stats_analysisd(request=mock_request)
    f_kwargs = {'filename': common.ANALYSISD_STATS
                }
    mock_dapi.assert_called_once_with(f=stats.deprecated_get_daemons_stats,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_stats_remoted(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_stats_remoted' endpoint is working as expected."""
    result = await get_stats_remoted(request=mock_request)
    f_kwargs = {'filename': common.REMOTED_STATS
                }
    mock_dapi.assert_called_once_with(f=stats.deprecated_get_daemons_stats,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_log(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_log' endpoint is working as expected."""
    result = await get_log(request=mock_request)
    f_kwargs = {'offset': 0,
                'limit': None,
                'sort_by': ['timestamp'],
                'sort_ascending': False,
                'search_text': None,
                'complementary_search': None,
                'tag': None,
                'level': None,
                'q': None,
                'select': None,
                'distinct': False
                }
    mock_dapi.assert_called_once_with(f=manager.ossec_log,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_log_summary(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_log_summary' endpoint is working as expected."""
    result = await get_log_summary(request=mock_request)
    mock_dapi.assert_called_once_with(f=manager.ossec_log_summary,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_api_config(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_api_config' endpoint is working as expected."""
    result = await get_api_config(request=mock_request)
    mock_dapi.assert_called_once_with(f=manager.get_api_config,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_restart(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'put_restart' endpoint is working as expected."""
    result = await put_restart(request=mock_request)
    mock_dapi.assert_called_once_with(f=manager.restart,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_conf_validation(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_conf_validation' endpoint is working as expected."""
    result = await get_conf_validation(request=mock_request)
    mock_dapi.assert_called_once_with(f=manager.validation,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
@patch('api.controllers.manager_controller.check_component_configuration_pair')
async def test_get_manager_config_ondemand(mock_check_pair, mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_manager_config_ondemand' endpoint is working as expected."""
    kwargs_param = {'configuration': 'configuration_value'
                    }
    result = await get_manager_config_ondemand(request=mock_request,
                                               component='component1',
                                               **kwargs_param)
    f_kwargs = {'component': 'component1',
                'config': kwargs_param.get('configuration', None)
                }
    mock_dapi.assert_called_once_with(f=manager.get_config,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.remove_nones_to_dict')
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_update_configuration(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'update_configuration' endpoint is working as expected."""
    with patch('api.controllers.manager_controller.Body.validate_content_type'):
        with patch('api.controllers.manager_controller.Body.decode_body') as mock_dbody:
            result = await update_configuration(request=mock_request,
                                                body={})
            f_kwargs = {'new_conf': mock_dbody.return_value}
            mock_dapi.assert_called_once_with(f=manager.update_ossec_conf,
                                              f_kwargs=mock_remove.return_value,
                                              request_type='local_any',
                                              is_async=False,
                                              wait_for_complete=False,
                                              logger=ANY,
                                              rbac_permissions=mock_request['token_info']['rbac_policies']
                                              )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(f_kwargs)
            assert isinstance(result, web_response.Response)


@pytest.mark.parametrize(
        "force_query,dapi_call_count,update_check", ([True, 2, True], [True, 1, False], [False, 1, True])
)
@pytest.mark.asyncio
@patch('api.controllers.manager_controller.configuration.update_check_is_enabled')
@patch('api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_check_available_version(
    mock_exc,
    mock_dapi,
    mock_dfunc,
    update_check_mock,
    force_query,
    dapi_call_count,
    update_check,
    mock_request=MagicMock()
):
    """Verify 'check_available_version' endpoint is working as expected."""
    app_context = {UPDATE_INFORMATION_KEY: {"foo": 1}, INSTALLATION_UID_KEY: "1234"}
    mock_request.app = app_context
    update_check_mock.return_value = update_check

    result = await check_available_version(request=mock_request, force_query=force_query)
    assert mock_dapi.call_count == dapi_call_count

    if force_query and update_check:
        mock_dapi.assert_any_call(
            f=query_update_check_service,
            f_kwargs={INSTALLATION_UID_KEY: app_context[INSTALLATION_UID_KEY]},
            request_type='local_master',
            is_async=True,
            logger=ANY,
        )
        mock_exc.assert_any_call(mock_dfunc.return_value)

    mock_dapi.assert_called_with(
        f=manager.get_update_information,
        f_kwargs={UPDATE_INFORMATION_KEY: app_context[UPDATE_INFORMATION_KEY]},
        request_type='local_master',
        is_async=False,
        logger=ANY,
    )
    mock_exc.assert_called_with(mock_dfunc.return_value)
    assert isinstance(result, web_response.Response)
