from typing import List
from sast.entity import FindingEntity
from sast.lifecycle_store import LifecycleStore


_lifecycle_store = LifecycleStore()


def apply_lifecycle(entities: List[FindingEntity]) -> None:
    """
    Mutates entities in-place with lifecycle data.
    """
    for entity in entities:
        _lifecycle_store.update(entity)
