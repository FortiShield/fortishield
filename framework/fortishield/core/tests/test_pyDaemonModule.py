# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest

from fortishield.core.pyDaemonModule import *
from fortishield.core.exception import FortishieldException
from tempfile import NamedTemporaryFile, TemporaryDirectory


@pytest.mark.parametrize('effect', [
   None,
   OSError(10000, 'Error')
])
@patch('fortishield.core.pyDaemonModule.sys.exit')
@patch('fortishield.core.pyDaemonModule.os.setsid')
@patch('fortishield.core.pyDaemonModule.sys.stderr.write')
@patch('fortishield.core.pyDaemonModule.sys.stdin.fileno')
@patch('fortishield.core.pyDaemonModule.os.dup2')
@patch('fortishield.core.pyDaemonModule.os.chdir')
def test_pyDaemon(mock_chdir, mock_dup, mock_fileno, mock_write, mock_setsid, mock_exit, effect):
    """Tests pyDaemon function works"""

    with patch('fortishield.core.pyDaemonModule.os.fork', return_value=255, side_effect=effect):
        pyDaemon()

    if effect == None:
        mock_exit.assert_called_with(0)
    else:
        mock_exit.assert_called_with(1)
    mock_setsid.assert_called_once_with()
    mock_chdir.assert_called_once_with('/')


@patch('fortishield.core.pyDaemonModule.common.FORTISHIELD_PATH', new='/tmp')
def test_create_pid():
    """Tests create_pid function works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with patch('fortishield.core.pyDaemonModule.common.OS_PIDFILE_PATH', new=tmpdirname.split('/')[2]):
            create_pid(tmpfile.name.split('/')[3].split('-')[0], '255')


@patch('fortishield.core.pyDaemonModule.common.FORTISHIELD_PATH', new='/tmp')
@patch('fortishield.core.pyDaemonModule.os.chmod', side_effect=OSError)
def test_create_pid_ko(mock_chmod):
    """Tests create_pid function exception works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with patch('fortishield.core.pyDaemonModule.common.OS_PIDFILE_PATH', new=tmpdirname.split('/')[2]):
            with pytest.raises(FortishieldException, match=".* 3002 .*"):
                create_pid(tmpfile.name.split('/')[3].split('-')[0], '255')


@patch('fortishield.core.pyDaemonModule.common.FORTISHIELD_PATH', new='/tmp')
def test_delete_pid():
    """Tests delete_pid function works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with patch('fortishield.core.pyDaemonModule.common.OS_PIDFILE_PATH', new=tmpdirname.split('/')[2]):
            delete_pid(tmpfile.name.split('/')[3].split('-')[0], '255')
