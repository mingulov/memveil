# SPDX-License-Identifier: GPL-3.0-or-later

"""Display-filter resolution over the device catalog.

The --device option accepts an exact device id or an exact
catalog name; rows always carry ids, so a name resolves to
its id before any renderer compares. Ids take precedence
over names when one device's name equals another's id, and
unknown filters pass through to match no rows.
"""

from memveil.model.report import Report
from memveil.model.session import DeviceEntry


def resolve_device_filter(
    devices: List[DeviceEntry], filt: String
) -> String:
    """Map an exact catalog name to its id; ids pass through."""
    if filt == "":
        return filt
    for i in range(len(devices)):
        if devices[i].device_id == filt:
            return filt
    for i in range(len(devices)):
        if devices[i].name == filt:
            return devices[i].device_id
    return filt


def device_filter_resolves(rep: Report, filt: String) -> Bool:
    """True when the filter would show device rows.

    Empty always resolves. Otherwise the filter must name
    a catalog id or name, or match an observed metric's
    device id after catalog resolution: live reports grow
    rows for devices no catalog entry admits yet.
    """
    if filt == "":
        return True
    for i in range(len(rep.devices)):
        if rep.devices[i].device_id == filt:
            return True
    for i in range(len(rep.devices)):
        if rep.devices[i].name == filt:
            return True
    var rid = resolve_device_filter(rep.devices, filt)
    for i in range(len(rep.metrics)):
        if (
            rep.metrics[i].has_device_id
            and rep.metrics[i].device_id == rid
        ):
            return True
    return False
