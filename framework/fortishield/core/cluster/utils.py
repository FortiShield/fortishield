# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import fcntl
import json
import logging
import os
import re
import signal
import socket
import time
import typing
from contextvars import ContextVar
from functools import lru_cache
from glob import glob
from operator import setitem

from fortishield.core import common, pyDaemonModule
from fortishield.core.configuration import get_ossec_conf
from fortishield.core.exception import FortishieldException, FortishieldError, FortishieldInternalError
from fortishield.core.results import FortishieldResult
from fortishield.core.utils import temporary_cache
from fortishield.core.fortishield_socket import create_fortishield_socket_message
from fortishield.core.wlogging import FortishieldLogger

logger = logging.getLogger('fortishield')
execq_lockfile = os.path.join(common.FORTISHIELD_PATH, "var", "run", ".api_execq_lock")


def read_cluster_config(config_file=common.OSSEC_CONF, from_import=False) -> typing.Dict:
    """Read cluster configuration from ossec.conf.

    If some fields are missing in the ossec.conf cluster configuration, they are replaced
    with default values.
    If there is no cluster configuration at all, the default configuration is marked as disabled.

    Parameters
    ----------
    config_file : str
        Path to configuration file.
    from_import : bool
        This flag indicates whether this function has been called from a module load (True) or from a function (False).

    Returns
    -------
    config_cluster : dict
        Dictionary with cluster configuration.
    """
    cluster_default_configuration = {
        'disabled': False,
        'node_type': 'master',
        'name': 'fortishield',
        'node_name': 'node01',
        'key': '',
        'port': 1516,
        'bind_addr': '0.0.0.0',
        'nodes': ['NODE_IP'],
        'hidden': 'no'
    }

    try:
        config_cluster = get_ossec_conf(section='cluster', conf_file=config_file, from_import=from_import)['cluster']
    except FortishieldException as e:
        if e.code == 1106:
            # If no cluster configuration is present in ossec.conf, return default configuration but disabling it.
            cluster_default_configuration['disabled'] = True
            return cluster_default_configuration
        else:
            raise FortishieldError(3006, extra_message=e.message)
    except Exception as e:
        raise FortishieldError(3006, extra_message=str(e))

    # If any value is missing from user's cluster configuration, add the default one.
    for value_name in set(cluster_default_configuration.keys()) - set(config_cluster.keys()):
        config_cluster[value_name] = cluster_default_configuration[value_name]

    if isinstance(config_cluster['port'], str) and not config_cluster['port'].isdigit():
        raise FortishieldError(3004, extra_message="Cluster port must be an integer.")

    config_cluster['port'] = int(config_cluster['port'])
    if config_cluster['disabled'] == 'no':
        config_cluster['disabled'] = False
    elif config_cluster['disabled'] == 'yes':
        config_cluster['disabled'] = True
    elif not isinstance(config_cluster['disabled'], bool):
        raise FortishieldError(3004,
                         extra_message=f"Allowed values for 'disabled' field are 'yes' and 'no'. "
                                       f"Found: '{config_cluster['disabled']}'")

    if config_cluster['node_type'] == 'client':
        logger.info("Deprecated node type 'client'. Using 'worker' instead.")
        config_cluster['node_type'] = 'worker'

    return config_cluster


@temporary_cache()
def get_manager_status(cache=False) -> typing.Dict:
    """Get the current status of each process of the manager.

    Raises
    ------
    FortishieldInternalError(1913)
        If /proc directory is not found or permissions to see its status are not granted.

    Returns
    -------
    data : dict
        Dict whose keys are daemons and the values are the status.
    """
    # Check /proc directory availability
    proc_path = "/proc"
    try:
        os.stat(proc_path)
    except (PermissionError, FileNotFoundError) as e:
        raise FortishieldInternalError(1913, extra_message=str(e))

    processes = ['fortishield-agentlessd', 'fortishield-analysisd', 'fortishield-authd', 'fortishield-csyslogd', 'fortishield-dbd', 'fortishield-monitord',
                 'fortishield-execd', 'fortishield-integratord', 'fortishield-logcollector', 'fortishield-maild', 'fortishield-remoted',
                 'fortishield-reportd', 'fortishield-syscheckd', 'fortishield-clusterd', 'fortishield-modulesd', 'fortishield-db', 'fortishield-apid']

    data, pidfile_regex, run_dir = {}, re.compile(r'.+\-(\d+)\.pid$'), os.path.join(common.FORTISHIELD_PATH, "var", "run")
    for process in processes:
        pidfile = glob(os.path.join(run_dir, f"{process}-*.pid"))
        if os.path.exists(os.path.join(run_dir, f"{process}.failed")):
            data[process] = 'failed'
        elif os.path.exists(os.path.join(run_dir, f".restart")):
            data[process] = 'restarting'
        elif os.path.exists(os.path.join(run_dir, f"{process}.start")):
            data[process] = 'starting'
        elif pidfile:
            # Iterate on pidfiles looking for the pidfile which has his pid in /proc,
            # if the loop finishes, all pidfiles exist but their processes are not running,
            # it means each process crashed and was not able to remove its own pidfile.
            data[process] = 'failed'
            for pid in pidfile:
                if os.path.exists(os.path.join(proc_path, pidfile_regex.match(pid).group(1))):
                    data[process] = 'running'
                    break

        else:
            data[process] = 'stopped'

    return data


def get_cluster_status() -> typing.Dict:
    """Get cluster status.

    Returns
    -------
    dict
        Cluster status.
    """
    cluster_status = {"enabled": "no" if read_cluster_config()['disabled'] else "yes"}
    try:
        cluster_status |= {"running": "yes" if get_manager_status()['fortishield-clusterd'] == 'running' else "no"}
    except FortishieldInternalError:
        cluster_status |= {"running": "no"}

    return cluster_status


def manager_restart() -> FortishieldResult:
    """Restart Fortishield manager.

    Send JSON message with the 'restart-fortishield' command to common.EXECQ_SOCKET socket.

    Raises
    ------
    FortishieldInternalError(1901)
        If the socket path doesn't exist.
    FortishieldInternalError(1902)
        If there is a socket connection error.
    FortishieldInternalError(1014)
        If there is a socket communication error.

    Returns
    -------
    FortishieldResult
        Confirmation message.
    """
    lock_file = open(execq_lockfile, 'a+')
    fcntl.lockf(lock_file, fcntl.LOCK_EX)
    try:
        # execq socket path
        socket_path = common.EXECQ_SOCKET
        # json msg for restarting Fortishield manager
        msg = json.dumps(create_fortishield_socket_message(origin={'module': common.origin_module.get()},
                                                     command=common.RESTART_FORTISHIELD_COMMAND,
                                                     parameters={'extra_args': [], 'alert': {}}))
        # initialize socket
        if os.path.exists(socket_path):
            try:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                conn.connect(socket_path)
            except socket.error:
                raise FortishieldInternalError(1902)
        else:
            raise FortishieldInternalError(1901)

        try:
            conn.send(msg.encode())
            conn.close()
        except socket.error as e:
            raise FortishieldInternalError(1014, extra_message=str(e))
    finally:
        fcntl.lockf(lock_file, fcntl.LOCK_UN)
        lock_file.close()
        read_config.cache_clear()

    return FortishieldResult({'message': 'Restart request sent'})


@lru_cache()
def get_cluster_items():
    """Load and return the content of cluster.json file as a dict.

    Returns
    -------
    cluster_items : dict
        Dictionary with the information inside cluster.json file.
    """
    try:
        here = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(common.FORTISHIELD_PATH, here, 'cluster.json')) as f:
            cluster_items = json.load(f)
        # Rebase permissions.
        list(map(lambda x: setitem(x, 'permissions', int(x['permissions'], base=0)),
                 filter(lambda x: 'permissions' in x, cluster_items['files'].values())))
        return cluster_items
    except Exception as e:
        raise FortishieldError(3005, str(e))


@lru_cache()
def read_config(config_file=common.OSSEC_CONF):
    """Get the cluster configuration.

    Parameters
    ----------
    config_file : str
        Path to configuration file.

    Returns
    -------
    dict
        Dictionary with cluster configuration.
    """
    return read_cluster_config(config_file=config_file)


# Context vars
context_tag: ContextVar[str] = ContextVar('tag', default='')


class ClusterFilter(logging.Filter):
    """
    Add cluster related information into cluster logs.
    """

    def __init__(self, tag: str, subtag: str, name: str = ''):
        """Class constructor.

        Parameters
        ----------
        tag : str
            First tag to show in the log - Usually describes class.
        subtag : str
            Second tag to show in the log - Usually describes function.
        name : str
            If name is specified, it names a logger which, together with its children, will have its events
            allowed through the filter. If name is the empty string, allows every event.
        """
        super().__init__(name=name)
        self.tag = tag
        self.subtag = subtag

    def filter(self, record):
        record.tag = context_tag.get() if context_tag.get() != '' else self.tag
        record.subtag = self.subtag
        return True

    def update_tag(self, new_tag: str):
        self.tag = new_tag

    def update_subtag(self, new_subtag: str):
        self.subtag = new_subtag


class ClusterLogger(FortishieldLogger):
    """
    Define the logger used by fortishield-clusterd.
    """

    def setup_logger(self):
        """
        Set ups cluster logger. In addition to super().setup_logger() this method adds:
            * A filter to add tag and subtags to cluster logs
            * Sets log level based on the "debug_level" parameter received from fortishield-clusterd binary.
        """
        super().setup_logger()
        self.logger.addFilter(ClusterFilter(tag='Cluster', subtag='Main'))
        debug_level = logging.DEBUG2 if self.debug_level == 2 else \
            logging.DEBUG if self.debug_level == 1 else logging.INFO

        self.logger.setLevel(debug_level)


def log_subprocess_execution(logger_instance: logging.Logger, logs: dict):
    """Log messages returned by functions that are executed in cluster's subprocesses.

    Parameters
    ----------
    logger_instance: Logger object
        Instance of the used logger.
    logs: dict
        Dict containing messages of different logging level.
    """
    if 'debug' in logs and logs['debug']:
        logger_instance.debug(f"{dict(logs['debug'])}")
    if 'debug2' in logs and logs['debug2']:
        logger_instance.debug2(f"{dict(logs['debug2'])}")
    if 'warning' in logs and logs['warning']:
        logger_instance.warning(f"{dict(logs['warning'])}")
    if 'error' in logs and logs['error']:
        logger_instance.error(f"{dict(logs['error'])}")
    if 'generic_errors' in logs and logs['generic_errors']:
        for error in logs['generic_errors']:
            logger_instance.error(error, exc_info=False)


def process_spawn_sleep(child):
    """Task to force the cluster pool spawn all its children and create their PID files.

    Parameters
    ----------
    child: int
        Process child number.
    """
    pid = os.getpid()
    pyDaemonModule.create_pid(f'fortishield-clusterd_child_{child}', pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    # Add a delay to force each child process to create its own PID file, preventing multiple calls
    # executed by the same child
    time.sleep(0.1)


async def forward_function(func: callable, f_kwargs: dict = None, request_type: str = 'local_master',
                           nodes: list = None, broadcasting: bool = False):
    """Distribute function to master node.

    Parameters
    ----------
    func : callable
        Function to execute on master node.
    f_kwargs : dict
        Function kwargs.
    request_type : str
        Request type.
    nodes : list
        System cluster nodes.
    broadcasting : bool
        Whether the function will be broadcasted or not.
    Returns
    -------
    Return either a dict or `FortishieldResult` instance in case the execution did not fail. Return an exception otherwise.
    """

    import concurrent
    from asyncio import run
    from fortishield.core.cluster.dapi.dapi import DistributedAPI
    dapi = DistributedAPI(f=func, f_kwargs=f_kwargs, request_type=request_type,
                          is_async=False, wait_for_complete=True, logger=logger, nodes=nodes,
                          broadcasting=broadcasting)
    pool = concurrent.futures.ThreadPoolExecutor()
    return pool.submit(run, dapi.distribute_function()).result()


def running_in_master_node() -> bool:
    """Determine if cluster is disabled or API is running in a master node.

    Returns
    -------
    bool
        True if API is running in master node or if cluster is disabled else False.
    """
    cluster_config = read_cluster_config()

    return cluster_config['disabled'] or cluster_config['node_type'] == 'master'