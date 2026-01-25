objection_log = []

def add_log(message):
    objection_log.append(message)
    print(message)
    if len(objection_log) > 200:
        objection_log.pop(0)

def get_log(clear: bool = False):
    data = list(objection_log)
    objection_log.clear()
    return data

    