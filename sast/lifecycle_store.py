from typing import Dict
from datetime import datetime
from sast.entity import FindingEntity


class LifecycleStore:
    """
    Simple lifecycle state store.
    Replace with DB / Redis later.
    """

    def __init__(self):
        self._state: Dict[str, FindingEntity] = {}

    def update(self, entity: FindingEntity) -> None:
        now = datetime.utcnow()

        if entity.entity_id not in self._state:
            # First time ever seen
            entity.first_seen = now
            entity.last_seen = now
            entity.times_seen = 1
            entity.resurfaced = False

            self._state[entity.entity_id] = entity
            return

        prev = self._state[entity.entity_id]

        entity.first_seen = prev.first_seen
        entity.last_seen = now
        entity.times_seen = prev.times_seen + 1

        # resurfaced = disappeared before and came back
        entity.resurfaced = (
            prev.last_seen is not None
            and (now - prev.last_seen).total_seconds() > 0
        )

        self._state[entity.entity_id] = entity
