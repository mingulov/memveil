# SPDX-License-Identifier: GPL-3.0-or-later

"""Display-filter resolution over the device catalog.

The --device option accepts an exact device id or an exact
catalog name; rows always carry ids, so a name resolves to
its id before any renderer compares. Ids take precedence
over names when one device's name equals another's id, and
unknown filters pass through to match no rows.
"""

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
