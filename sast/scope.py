def in_scope(entity, policy):
    if entity.file.startswith("tests/"):
        return False
    if entity.severity == "LOW" and policy.ignore_low:
        return False
    return True
