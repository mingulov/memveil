# SPDX-License-Identifier: GPL-3.0-or-later

"""Validated range resolution for region observations.

`resolve_region` maps one source observation onto a region
reference with an explicit resolution level. Only an
explicitly admitted (identity, namespace, generation) triple
with a proven contiguous span yields physical_span; a known
identity without that proof stays identity_only, and anything
else is unavailable. Matching is exact on all three fields:
a recycled identity under a new generation, or the same
token under another namespace, never inherits an admission.

There is no address arithmetic path. Offsets are relative to
the region identity, and no virt_to_phys-style formula, page
table walk, or numeric coincidence across namespaces can
produce a physical span. Admitted mappings come from
validated platform evidence supplied by the caller; no
resolver fields exist on any shipped profile because no such
source is validated yet.
"""

from memveil.model.identity import check_generation
from memveil.model.regions import (
    RegionReference,
    check_region_space,
    check_region_span,
)
from memveil.model.validate import ValidationError, check_opaque_id


struct RawRange(ImplicitlyCopyable):
    """One source observation before resolution."""

    var identity: String
    var namespace: String
    var offset: UInt64
    var length: UInt64
    var generation: Int

    def __init__(out self):
        self.identity = String("")
        self.namespace = String("")
        self.offset = UInt64(0)
        self.length = UInt64(0)
        self.generation = 1


struct AdmittedMapping(ImplicitlyCopyable):
    """One validated contiguity proof for an identity triple."""

    var identity: String
    var namespace: String
    var generation: Int
    var proven_span: Bool

    def __init__(out self):
        self.identity = String("")
        self.namespace = String("")
        self.generation = 1
        self.proven_span = False


def resolve_region(
    obs: RawRange, admitted: List[AdmittedMapping]
) raises -> RegionReference:
    """Resolve one observation against explicit admissions."""
    try:
        check_opaque_id(obs.identity)
    except e:
        raise ValidationError("region identity", String(e))
    check_region_space(obs.namespace)
    _ = check_region_span(obs.offset, obs.length)
    check_generation(obs.generation)
    var level = String("unavailable")
    if obs.namespace == "identity_only":
        level = String("identity_only")
    else:
        for i in range(len(admitted)):
            var m = admitted[i]
            if (
                m.identity == obs.identity
                and m.namespace == obs.namespace
                and m.generation == obs.generation
            ):
                if m.proven_span:
                    level = String("physical_span")
                else:
                    level = String("identity_only")
                break
    return RegionReference.checked(
        obs.namespace, level, obs.identity, obs.offset,
        obs.length, obs.generation,
    )
