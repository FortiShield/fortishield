# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from fortishield.core.common import QUEUE_SOCKET
from fortishield.core.exception import FortishieldError
from fortishield.core.results import FortishieldResult, AffectedItemsFortishieldResult
from fortishield.core.fortishield_queue import FortishieldAnalysisdQueue
from fortishield.rbac.decorators import expose_resources

MSG_HEADER = '1:API-Webhook:'


@expose_resources(actions=["event:ingest"], resources=["*:*:*"], post_proc_func=None)
def send_event_to_analysisd(events: list) -> FortishieldResult:
    """Send events to analysisd through the socket.

    Parameters
    ----------
    events : list
        List of events to send.

    Returns
    -------
    FortishieldResult
        Confirmation message.
    """
    result = AffectedItemsFortishieldResult(
        all_msg="All events were forwarded to analisysd",
        some_msg="Some events were forwarded to analisysd",
        none_msg="No events were forwarded to analisysd"
    )

    with FortishieldAnalysisdQueue(QUEUE_SOCKET) as queue:
        for event in events:
            try:
                queue.send_msg(msg_header=MSG_HEADER, msg=event)
                result.affected_items.append(event)
            except FortishieldError as error:
                result.add_failed_item(event, error=error)

    result.total_affected_items = len(result.affected_items)
    return result
