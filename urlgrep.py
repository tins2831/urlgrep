import re
import os
import sys
import threading

BASE_DIR = os.path.dirname(__file__)

def _gen_endp_exts():
    rgx = []

    # https://gist.github.com/securifera/e7eed730cbe1ce43d0c29d7cd2d582f4
    with open(os.path.join(BASE_DIR, 'extensions.txt'), 'r') as exts:
        for ext in exts:
            ext = re.sub("^\\.", "", ext)
            ext = ext.replace("-", "\\-")

            rgx.append(ext.strip())

    return '|'.join(rgx)

WORKERS = 4 # number of threads to use and the number of file chunks to generate

# https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py#L29
REGEX = (
    "(?:\"|')(((?:[a-zA-Z]{1,10}://|//)(?:[^\"'/]){1,}\\.[a-zA-Z0-9]+" +
    "[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\[\\]][^\"" +
    "'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[" +
    "a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-/]{1" +
    ",}/[a-zA-Z0-9_\\-/]{3,}(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-]" +
    "{1,}\\.(?:%s)(?:[\\?|#][^\"|']{0,}|))|\\d+\\.\\d+\\.\\d+\\.\\d+|" +
    "(?:[a-zA-Z]{1,10}://|//))(?:\"|')"
)
REGEX = REGEX % _gen_endp_exts()

def _split_list(l, c_len):
    q = int(len(l) / c_len)

    for x in range(0, len(l), q):
        yield l[x : x + q]

results = []
def process_chunk(c):
    try:
        for chunk in c:
            for f in chunk[1]:
                if halt_ev.is_set():
                    return

                fpath = os.path.join(chunk[0], f)
                fobj = open(fpath, 'r')
                idx = 0
                result_group = []
                
                for match in re.finditer(REGEX, fobj.read()):
                    if halt_ev.is_set():
                        fobj.close()

                        return

                    line_nm = match.string[:match.end(0)].count('\n') + 1
                    idx += 1

                    result_group.append({
                        'fpath': fpath,
                        'idx': idx,
                        'line': line_nm,
                        'match': match[0]
                    })

                results.append(result_group)

                fobj.close()
    except Exception as e:
        print(e)

        halt_ev.set()
        return

to_process = []
if os.path.isdir(sys.argv[1]):
    for parent, _, files in os.walk(sys.argv[1]):
        if len(files) == 0:
            continue

        to_process.append([parent, files])
else:
    to_process.append(
        [
            os.path.dirname(sys.argv[1]),
            [os.path.basename(sys.argv[1])]
        ]
    )

    WORKERS = 1

halt_ev = threading.Event()
workers = []
for chunk in _split_list(to_process, WORKERS):
    worker = threading.Thread(target = process_chunk, args = [chunk])

    worker.daemon = True

    workers.append(worker)
    worker.start()

for worker in workers:
    try:
        worker.join()
    except Exception as e:
        print(e)

        halt_ev.set()

formatted_results = []
for result in results:
    if len(result) == 0:
        continue

    formatted_group = []

    for group in result:
        formatted_group.append("[ %d ] %s:%d:%s%s" %
            (
                group['idx'],
                group['fpath'],
                group['line'],
                chr(0x20) * 4, # padding 4 spaces
                group['match']
            )
        )

    formatted_results.append(formatted_group)

print('\n\n'.join(['\n'.join(group) for group in formatted_results]))
