import psutil

def scan():
    data = {}
    data['cpu'] = {
        'count': psutil.cpu_count(),
        'percent': psutil.cpu_percent(interval=1),
    }
    mem = psutil.virtual_memory()
    data['ram'] = {
        'total': mem.total,
        'used': mem.used,
        'percent': mem.percent
    }
    data['gpu'] = {'info': 'Not implemented yet'}
    return data
