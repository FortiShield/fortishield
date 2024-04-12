# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from unittest.mock import patch

import pytest

from api.models.configuration_model import HTTPSModel

with patch('khulnasoft.common.fortishield_uid'):
    with patch('khulnasoft.common.fortishield_gid'):
        from api.encoder import prettify, dumps
        from fortishield.core.results import fortishieldResult


def custom_hook(dct):
    if 'key' in dct:
        return HTTPSModel.from_dict(dct)
    elif 'error' in dct:
        return FortishieldResult.decode_json({'result': dct, 'str_priority': 'v2'})
    else:
        return dct


@pytest.mark.parametrize('o', [HTTPSModel(key='v1'),
                               FortishieldResult({'k1': 'v1'}, str_priority='v2')
                               ]
                         )
def test_encoder_dumps(o):
    """Test dumps method from API encoder using FortishieldAPIJSONEncoder."""
    encoded = dumps(o)
    decoded = json.loads(encoded, object_hook=custom_hook)
    assert decoded == o


def test_encoder_prettify():
    """Test prettify method from API encoder using FortishieldAPIJSONEncoder."""
    assert prettify({'k1': 'v1'}) == '{\n   "k1": "v1"\n}'
