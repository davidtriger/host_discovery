from subprocess import Popen, PIPE, DEVNULL


# Match a banner from provided xml filename to a recog result
def match(banner, filename):
    proc = Popen(["recog/bin/recog_match", "recog/xml/" + filename + ".xml"], stdout=PIPE, stdin=PIPE, stderr=DEVNULL)
    grep_stdout = proc.communicate(input=bytearray(banner, encoding='utf8'))[0]
    proc.terminate()

    return grep_stdout.decode()

