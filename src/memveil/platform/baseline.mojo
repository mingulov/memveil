# SPDX-License-Identifier: GPL-3.0-or-later

"""Real baseline observations, kept separate from events.

`read_baseline` extracts the producer-attested initial region
intervals retained on the parsed session: state plus
provenance, never invented transitions. Late attach seeds the
tracker from these observations; an unmap in a shared pool
releases an allocation without reprivatizing the baseline.
`check_observation` validates directly built observations for
API users. Extracted observations are not re-validated here:
the session parser already enforced every bound, and a second
copy of those checks would drift.
"""

from memveil.model.identity import check_generation
from memveil.model.regions import (
    RegionObservation,
    check_region_space,
    check_region_span,
    check_region_state,
)
from memveil.model.session import Session
from memveil.model.validate import (
    ValidationError,
    check_bounded_text,
    check_opaque_id,
)


def check_observation(obs: RegionObservation) raises:
    """Validate one directly built baseline observation."""
    try:
        check_opaque_id(obs.region_id)
    except e:
        raise ValidationError("region_id", String(e))
    check_region_state(obs.state)
    _ = check_region_span(obs.offset, obs.length)
    check_region_space(obs.address_space)
    check_bounded_text(obs.provenance, 1, 512, "region provenance")
    check_generation(obs.generation)


def read_baseline(session: Session) -> List[RegionObservation]:
    """Copy the session's retained baseline observations out."""
    return session.baseline_regions.copy()
