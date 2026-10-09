# SPDX-License-Identifier: GPL-3.0-or-later

"""Opaque correlation identities and registry budgets.

Operation, mapping, device, and pool identities are session-local
opaque tokens: they name observations, never raw kernel addresses.
Every pairing key carries its address-space namespace, so the same
token under another device or namespace never merges. Generations
are positive per (device, namespace, token) lineages; a reused
address gets a new generation, never a resurrected mapping.

Budgets below are allocation ceilings from the frozen product
contracts, not eager allocations. Each bounded store proves its
N/N+1 behavior with a deterministic refusal plus quality change;
no registry retains unbounded session history.
"""

from memveil.model.validate import ValidationError, check_opaque_id

comptime PENDING_MAX = 65536
comptime ACTIVE_MAX = 65536
comptime NESTED_MAX = 8
comptime RESOLVED_MAX = 16384
comptime RETIRED_MAX = 16384
comptime DEVICE_MAX_ID = 4096
comptime POOL_MAX = 1024
comptime REGION_MAX = 4096
comptime DIAG_MAX = 2048


def check_address_space(v: String) raises:
    """Accept exactly kvirt, gphys, iova, or tlb-phys."""
    if v == "kvirt" or v == "gphys" or v == "iova" or v == "tlb-phys":
        return
    raise ValidationError("address_space", "unknown namespace")


def check_generation(g: Int) raises:
    """Generations are positive."""
    if g >= 1:
        return
    raise ValidationError("generation", "must be positive")


struct OperationId(ImplicitlyCopyable):
    """One session-local operation token."""

    var value: String

    def __init__(out self):
        self.value = String("")

    @staticmethod
    def parse(text: String) raises -> Self:
        try:
            check_opaque_id(text)
        except e:
            raise ValidationError("operation_id", String(e))
        var out = Self()
        out.value = text
        return out^


struct MappingId(ImplicitlyCopyable):
    """One session-local mapping token."""

    var value: String

    def __init__(out self):
        self.value = String("")

    @staticmethod
    def parse(text: String) raises -> Self:
        try:
            check_opaque_id(text)
        except e:
            raise ValidationError("mapping_id", String(e))
        var out = Self()
        out.value = text
        return out^


struct DeviceRef(ImplicitlyCopyable):
    """One interned device token."""

    var value: String

    def __init__(out self):
        self.value = String("")

    @staticmethod
    def parse(text: String) raises -> Self:
        try:
            check_opaque_id(text)
        except e:
            raise ValidationError("device_id", String(e))
        var out = Self()
        out.value = text
        return out^


struct PoolRef(ImplicitlyCopyable):
    """One pool token."""

    var value: String

    def __init__(out self):
        self.value = String("")

    @staticmethod
    def parse(text: String) raises -> Self:
        try:
            check_opaque_id(text)
        except e:
            raise ValidationError("pool_id", String(e))
        var out = Self()
        out.value = text
        return out^


@fieldwise_init
struct PairingKey(ImplicitlyCopyable):
    """Namespace-aware correlation key.

    The rendered form joins device, namespace, and token with a
    separator outside the opaque-id charset, so distinct triples
    never collide. Prefer checked() for untrusted input.
    """

    var device: String
    var namespace: String
    var token: String

    @staticmethod
    def checked(
        device: String, namespace: String, token: String
    ) raises -> Self:
        try:
            check_opaque_id(device)
        except e:
            raise ValidationError("pairing.device", String(e))
        check_address_space(namespace)
        try:
            check_opaque_id(token)
        except e:
            raise ValidationError("pairing.token", String(e))
        return Self(device, namespace, token)

    def render(self) -> String:
        return self.device + "|" + self.namespace + "|" + self.token
