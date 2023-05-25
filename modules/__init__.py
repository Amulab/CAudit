def convert_size(raw):
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = 1024
    for i in range(len(units)):
        if raw / size < 1:
            return "%.2f%s" % (raw, units[i])
        raw = raw / size