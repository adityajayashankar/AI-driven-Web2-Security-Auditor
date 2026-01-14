def plan_tasks(entities):
    tasks = []

    for e in entities:
        if e.category == "MULTI" and e.confidence == "HIGH":
            tasks.append(create_fix_task(e))

        elif e.category == "SCA" and e.severity == "LOW":
            tasks.append(create_backlog_task(e))

    return tasks
