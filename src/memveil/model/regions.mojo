# SPDX-License-Identifier: GPL-3.0-or-later

"""Region identity, observation, and reference types.

A region is one opaque session-local identity plus the
address-space namespace its offsets are relative to. Offsets
are relative to the region identity, never raw kernel
addresses, and equality across namespaces needs a validated
resolver: the same token under another namespace never
merges. Generations separate successive lives of one token;
state, resolution, and provenance checks live here so every
consumer shares one definition.
"""

from memveil.model.identity import check_generation
from memveil.model.validate import (
    ValidationError,
    check_opaque_id,
    checked_add,
)


struct RegionObservation(ImplicitlyCopyable):
    """One producer-attested initial region interval."""

    var region_id: String
    var state: String
    var offset: UInt64
    var length: UInt64
    var address_space: String
    var provenance: String
    var generation: Int

    def __init__(out self):
        self.region_id = String("")
        self.state = String("")
        self.offset = UInt64(0)
        self.length = UInt64(0)
        self.address_space = String("")
        self.provenance = String("")
        self.generation = 1


struct RegionReference(ImplicitlyCopyable):
    """One resolved region range with its resolution proof level."""

    var namespace: String
    var resolution: String
    var identity: String
    var offset: UInt64
    var length: UInt64
    var generation: Int

    def __init__(out self):
        self.namespace = String("")
        self.resolution = String("")
        self.identity = String("")
        self.offset = UInt64(0)
        self.length = UInt64(0)
        self.generation = 1

    def key(self) -> String:
        """Render namespace, generation, and token as one key.

        The separator stays outside the opaque-id charset, so
        distinct triples never collide.
        """
        return (
            self.namespace
            + "|"
            + String(self.generation)
            + "|"
            + self.identity
        )

    @staticmethod
    def checked(
        namespace: String,
        resolution: String,
        identity: String,
        offset: UInt64,
        length: UInt64,
        generation: Int,
    ) raises -> Self:
        """Build one reference from validated fields."""
        check_region_space(namespace)
        check_region_resolution(resolution)
        try:
            check_opaque_id(identity)
        except e:
            raise ValidationError("region identity", String(e))
        _ = check_region_span(offset, length)
        check_generation(generation)
        var out = Self()
        out.namespace = namespace
        out.resolution = resolution
        out.identity = identity
        out.offset = offset
        out.length = length
        out.generation = generation
        return out^


def check_region_state(v: String) raises:
    """Accept exactly shared, private, or unknown."""
    if v == "shared" or v == "private" or v == "unknown":
        return
    raise ValidationError("region_state", "bad enum")


def check_region_space(v: String) raises:
    """Accept exactly the four schema address spaces."""
    if (
        v == "guest_physical"
        or v == "kernel_virtual"
        or v == "iova"
        or v == "identity_only"
    ):
        return
    raise ValidationError("address_space", "bad enum")


def check_region_resolution(v: String) raises:
    """Accept exactly the three resolution levels."""
    if (
        v == "physical_span"
        or v == "identity_only"
        or v == "unavailable"
    ):
        return
    raise ValidationError("resolution", "bad enum")


def check_region_span(offset: UInt64, length: UInt64) raises -> UInt64:
    """Return the half-open end, refusing overflow."""
    try:
        return checked_add(offset, length)
    except:
        raise ValidationError("region span", "span overflows")
