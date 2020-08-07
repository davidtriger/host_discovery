from subprocess import Popen, PIPE, DEVNULL
import re
import json
from enum import Enum


class MatchLevel(Enum):
    RAW = 1
    SPLIT_HEX = 2
    SPLIT_NON_ALPHABETIC = 3

    # Comparison operator for checking level
    def __ge__(self, other):
        return self.value >= other.value


# Filter nmap output and then try to match
def match_nmap(banner, filename, level=MatchLevel.RAW):
    MIN_WORD_LENGTH = 2

    # Level RAW
    match_result = match(banner, filename)

    if match_result is None and level >= MatchLevel.SPLIT_HEX:
        # Level SPLIT_HEX
        split_hex = re.split(r"\\x\w\w+|\n", banner)

        for word in split_hex: 
            if len(word) > MIN_WORD_LENGTH:
                match_result = match(word, filename)

                if match_result is not None:
                    return match_result

        if level >= MatchLevel.SPLIT_NON_ALPHABETIC:
            # Level SPLIT_NON_ALPHABETIC
            for word in split_hex: 
                for part_word in re.split(r"\W+", word):
                    # Do not process numbers only, causes high probability of false match
                    if len(part_word) > MIN_WORD_LENGTH and not part_word.isdigit():
                        match_result = match(part_word, filename)

                        if match_result is not None:
                            return match_result

    return match_result 


# Match a banner from provided xml filename to a recog result
def match(banner, filename):
    proc = Popen(["recog/bin/recog_match", "recog/xml/" + filename + ".xml"], stdout=PIPE, stdin=PIPE, stderr=DEVNULL)
    grep_stdout = proc.communicate(input=bytearray(banner, encoding='utf8'))[0]
    proc.terminate()

    match_result = grep_stdout.decode()
    
    try:
        if match_result.startswith("MATCH:"):
            match_result = match_result[7:].replace("=>", ":")
            match_object = json.loads(match_result)
        else:
            match_object = None
    except Exception as e:
        print("Error parsing recog result: ", e)

    return match_object


