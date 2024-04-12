# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from functools import wraps

from aiohttp import web

import fortishield.ciscat as ciscat
import fortishield.rootcheck as rootcheck
import fortishield.syscheck as syscheck
import fortishield.syscollector as syscollector
from api import configuration
from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc, deprecate_endpoint
from fortishield.core.cluster.dapi.dapi import DistributedAPI
from fortishield.core.exception import fortishieldResourceNotFound

logger = logging.getLogger('fortishield-api')


def check_experimental_feature_value(func):
    """Decorator used to check whether the experimental features are enabled in the API configuration or not."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not configuration.api_conf['experimental_features']:
            raise_if_exc(FortishieldResourceNotFound(1122))
        else:
            return func(*args, **kwargs)

    return wrapper


@check_experimental_feature_value
async def clear_rootcheck_database(request, pretty: bool = False, wait_for_complete: bool = False,
                                   agents_list: list = None) -> web.Response:
    """Clear the rootcheck database for all the agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : list
        List of agent's IDs.

    Returns
    -------
    web.Response
        API response.
    """
    # If we use the 'all' keyword and the request is distributed_master, agents_list must be '*'
    if 'all' in agents_list:
        agents_list = '*'

    f_kwargs = {'agent_list': agents_list}

    dapi = DistributedAPI(f=rootcheck.clear,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
@check_experimental_feature_value
async def clear_syscheck_database(request, pretty: bool = False, wait_for_complete: bool = False,
                                  agents_list: list = None) -> web.Response:
    """Clear the syscheck database for all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : list
        List of agent's IDs.

    Returns
    -------
    web.Response
        API response.
    """
    # If we use the 'all' keyword and the request is distributed_master, agents_list must be '*'
    if 'all' in agents_list:
        agents_list = '*'

    f_kwargs = {'agent_list': agents_list}

    dapi = DistributedAPI(f=syscheck.clear,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@check_experimental_feature_value
async def get_cis_cat_results(request, pretty: bool = False, wait_for_complete: bool = False, agents_list: str = '*',
                              offset: int = 0, limit: int = None, select: str = None, sort: str = None,
                              search: str = None, benchmark: str = None, profile: str = None, fail: int = None,
                              error: int = None, notchecked: int = None, unknown: int = None,
                              score: int = None) -> web.Response:
    """Get ciscat results info from all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    agents_list : str
        List of agent's IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    benchmark : str
        Filters by benchmark type.
    profile : str
        Filters by evaluated profile.
    fail : int
        Filters by failed checks.
    error : int
        Filters by encountered errors.
    notchecked : int
        Filters by notchecked value.
    unknown : int
        Filters by unknown results.
    score : int
        Filters by final score.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'benchmark': benchmark,
                    'profile': profile,
                    'fail': fail,
                    'error': error,
                    'notchecked': notchecked,
                    'unknown': unknown,
                    'score': score,
                    'pass': request.query.get('pass', None)
                }
                }

    dapi = DistributedAPI(f=ciscat.get_ciscat_results,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
@check_experimental_feature_value
async def get_hardware_info(request, pretty: bool = False, wait_for_complete: bool = False, agents_list: str = '*',
                            offset: int = 0, limit: int = None, select: str = None, sort: str = None,
                            search: str = None, board_serial: str = None) -> web.Response:
    """Get hardware info from all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    agents_list : str
        List of agent's IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    board_serial : str
        Filters by board_serial value.

    Returns
    -------
    web.Response
        API response.
    """
    filters = {
        'board_serial': board_serial
    }
    # Add nested fields to kwargs filters
    nested = ['ram.free', 'ram.total', 'cpu.cores', 'cpu.mhz', 'cpu.name']
    for field in nested:
        filters[field] = request.query.get(field, None)
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'hardware'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
@check_experimental_feature_value
async def get_network_address_info(request, pretty: bool = False, wait_for_complete: bool = False,
                                   agents_list: str = '*', offset: int = 0, limit: str = None, select: str = None,
                                   sort: str = None, search: str = None, iface_name: str = None, proto: str = None,
                                   address: str = None, broadcast: str = None, netmask: str = None) -> web.Response:
    """Get the IPv4 and IPv6 addresses associated to all network interfaces.

    Parameters
    ----------
    request : connexion.request
    agents_list : str
        List of agent's IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    iface_name : str
        Filters by interface name.
    proto : str
        Filters by IP protocol.
    address : str
        Filters by IP address associated with the network interface.
    broadcast : str
        Filters by broadcast address.
    netmask : str
        Filters by netmask.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'iface_name': iface_name,
                    'proto': proto,
                    'address': address,
                    'broadcast': broadcast,
                    'netmask': netmask
                },
                'element_type': 'netaddr'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
@check_experimental_feature_value
async def get_network_interface_info(request, pretty: bool = False, wait_for_complete: bool = False,
                                     agents_list: str = '*', offset: int = 0, limit: int = None, select: str = None,
                                     sort: str = None, search: str = None, adapter: str = None, state: str = None,
                                     mtu: str = None) -> web.Response:
    """Get all network interfaces from all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    agents_list : str
        List of agent's IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    adapter : str
        Filters by adapter.
    state : str
        Filters by state.
    mtu : str
        Filters by mtu.

    Returns
    -------
    web.Response
        API response.
    """
    filters = {
        'adapter': adapter,
        'type': request.query.get('type', None),
        'state': state,
        'mtu': mtu
    }
    # Add nested fields to kwargs filters
    nested = ['tx.packets', 'rx.packets', 'tx.bytes', 'rx.bytes', 'tx.errors', 'rx.errors', 'tx.dropped', 'rx.dropped']
    for field in nested:
        filters[field] = request.query.get(field, None)

    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'netiface'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
@check_experimental_feature_value
async def get_network_protocol_info(request, pretty: bool = False, wait_for_complete: bool = False,
                                    agents_list: str = '*', offset: int = 0, limit: int = None, select: str = None,
                                    sort: str = None, search: str = None, iface: str = None, gateway: str = None,
                                    dhcp: str = None) -> web.Response:
    """Get network protocol info from all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    agents_list : str
        List of agent's IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    iface : str
        Filters by iface.
    gateway : str
        Filters by gateway.
    dhcp : str
        Filters by dhcp.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'iface': iface,
                    'type': request.query.get('type', None),
                    'gateway': gateway,
                    'dhcp': dhcp
                },
                'element_type': 'netproto'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
@check_experimental_feature_value
async def get_os_info(request, pretty: bool = False, wait_for_complete: bool = False, agents_list: str = '*',
                      offset: int = 0, limit: int = None, select: str = None, sort: str = None, search: str = None,
                      os_name: str = None, architecture: str = None, os_version: str = None, version: str = None,
                      release: str = None) -> web.Response:
    """Get OS info from all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    agents_list : str
        List of agent's IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    os_name : str
        Filters by os_name.
    architecture : str
        Filters by architecture.
    os_version : str
        Filters by os_version.
    version : str
        Filters by version.
    release : str
        Filters by release.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'os_name': os_name,
                    'architecture': architecture,
                    'os_version': os_version,
                    'version': version,
                    'release': release
                },
                'element_type': 'os'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
@check_experimental_feature_value
async def get_packages_info(request, pretty: bool = False, wait_for_complete: bool = False, agents_list: str = '*',
                            offset: int = 0, limit: int = None, select: str = None, sort: str = None,
                            search: str = None, vendor: str = None, name: str = None, architecture: str = None,
                            version: str = None) -> web.Response:
    """Get packages info from all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    agents_list : str
        List of agent's IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    vendor : str
        Filters by vendor.
    name : str
        Filters by name.
    architecture : str
        Filters by architecture.
    version : str
        Filters by version.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'vendor': vendor,
                    'name': name,
                    'architecture': architecture,
                    'format': request.query.get('format', None),
                    'version': version
                },
                'element_type': 'packages'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
@check_experimental_feature_value
async def get_ports_info(request, pretty: bool = False, wait_for_complete: bool = False, agents_list: str = '*',
                         offset: int = 0, limit: int = None, select: str = None, sort: str = None, search: str = None,
                         pid: str = None, protocol: str = None, tx_queue: str = None, state: str = None,
                         process: str = None) -> web.Response:
    """Get ports info from all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    agents_list : str
        List of agent's IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    pid : str
        Filters by pid.
    protocol : str
        Filters by protocol.
    tx_queue : str
        Filters by tx_queue.
    state : str
        Filters by state.
    process : str
        Filters by process.

    Returns
    -------
    web.Response
        API response.
    """
    filters = {
        'pid': pid,
        'protocol': protocol,
        'tx_queue': tx_queue,
        'state': state,
        'process': process
    }
    # Add nested fields to kwargs filters
    nested = ['local.ip', 'local.port', 'remote.ip']
    for field in nested:
        filters[field] = request.query.get(field, None)

    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'ports'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
@check_experimental_feature_value
async def get_processes_info(request, pretty: bool = False, wait_for_complete: bool = False, agents_list: str = '*',
                             offset: int = 0, limit: int = None, select: str = None, sort: str = None,
                             search: str = None, pid: str = None, state: str = None, ppid: str = None,
                             egroup: str = None, euser: str = None, fgroup: str = None, name: str = None,
                             nlwp: str = None, pgrp: str = None, priority: str = None, rgroup: str = None,
                             ruser: str = None, sgroup: str = None, suser: str = None) -> web.Response:
    """Get processes info from all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    agents_list : str
        List of agent's IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    pid : str
        Filters by pid.
    state : str
        Filters by state.
    ppid : str
        Filters by process parent pid.
    egroup : str
        Filters by process egroup.
    euser : str
        Filters by process euser.
    fgroup : str
        Filters by process fgroup.
    name : str
        Filters by process name.
    nlwp : str
        Filters by process nlwp.
    pgrp : str
        Filters by process pgrp.
    priority : str
        Filters by process priority.
    rgroup : str
        Filters by process rgroup.
    ruser : str
        Filters by process ruser.
    sgroup : str
        Filters by process sgroup.
    suser : str
        Filters by process suser.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'state': state,
                    'pid': pid,
                    'ppid': ppid,
                    'egroup': egroup,
                    'euser': euser,
                    'fgroup': fgroup,
                    'name': name,
                    'nlwp': nlwp,
                    'pgrp': pgrp,
                    'priority': priority,
                    'rgroup': rgroup,
                    'ruser': ruser,
                    'sgroup': sgroup,
                    'suser': suser
                },
                'element_type': 'processes'
                }

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
@check_experimental_feature_value
async def get_hotfixes_info(request, pretty: bool = False, wait_for_complete: bool = False, agents_list: str = '*',
                            offset: int = 0, limit: int = None, sort: str = None, search: str = None,
                            select: str = None, hotfix: str = None) -> web.Response:
    """Get hotfixes info from all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    agents_list : str
        List of agent's IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    select : str
        Select which fields to return (separated by comma).
    hotfix : str
        Filters by hotfix in Windows agents.

    Returns
    -------
    web.Response
        API response.
    """
    filters = {'hotfix': hotfix}

    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': filters,
                'element_type': 'hotfixes'}

    dapi = DistributedAPI(f=syscollector.get_item_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
