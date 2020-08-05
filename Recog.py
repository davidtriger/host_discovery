from subprocess import Popen, PIPE, STDOUT


# Match a banner from operating system to a recog result
def match_os(banner):
    proc = Popen(["recog/bin/recog_match", "recog/xml/operating_system.xml"], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    grep_stdout = proc.communicate(input=bytearray(banner+"\n", encoding='utf8'))[0]
    print(grep_stdout.decode())
    proc.terminate()
    
