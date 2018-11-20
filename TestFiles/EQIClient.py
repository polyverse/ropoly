# Set go_parent_dir to the folder that your installation of go is in.
# Clone ropoly into go/src/github.com/polyverse/ropoly.
go_parent_dir = "/usr/local"

fingerprints = ("original", "allDead", "ASLR1", "ASLR1000", "ASLR1Plus1000", "originalPlusASLR1", "thousandOffsets", \
                "thousandLargeFarOffsets", "thousandLargeCloseOffsets", "thousandOffsetsHalfSurvived", \
                "twoThousandOffsetsDoubled", "thousandOffsetsDoubled", "fiveHundredOffsets", "hundredOffsets", \
                "tenOffsets", "twoOffsets")

# Set eqi_funcs to the list of EQI functions you want to use.
# Name of function first, followed by list of arguments.
eqi_funcs = (
    ["envisen-original", {}],
    ["monte-carlo", {"min":2, "max":10, "trials":1000000}],
    ["monte-carlo", {"min":2, "max":2, "trials":1000000}],
    ["count-poly", {}],
    ["count-poly", {"order":3}],
    ["count-poly", {"single":"true"}],
    ["count-poly", {"single":"true", "order":3}],
    ["count-exp", {"single":"true"}],
    )

function = 0
arguments = 1
relative_directory = "TestFiles/fingerprints/"
server_absolute_directory = "/go/src/github.com/polyverse/ropoly/" + relative_directory
client_absolute_directory = go_parent_dir + server_absolute_directory
url_prefix = "http://localhost:8008/api/v1/"
comparison_suffix = "_c"

import urllib.request as r
import json

def main():
    scenarios = []
    eqis = []
    for fingerprint in fingerprints:

        comparison_url = url_prefix + "compare?old=" + relative_directory + fingerprints[0] \
                         + "&new=" + relative_directory + fingerprint
        comparison_file = fingerprint + comparison_suffix
        http_to_file(comparison_url, client_absolute_directory + comparison_file)

        pair_eqis = []
        for func in eqi_funcs:
            eqi_url = url_prefix + "eqi?comparison=" + relative_directory + comparison_file + "&func=" + func_to_string(func)
            eqi = ""
            try:
                eqi = http_to_string(eqi_url)
            except Exception as e:
                print("Error for URL", eqi_url.replace("&", "\\&"))
                eqi = str(e)
            pair_eqis.append(eqi)
        eqis.append(pair_eqis)

    csv_file = client_absolute_directory +  "eqis.csv"
    arr2d_to_csv(eqis, csv_file, funcs_to_strings(), fingerprints)

def func_to_string(func):
    ret = func[function]
    for arg in func[arguments]:
        ret += "&" + arg + "=" + str(func[arguments][arg])
    return ret

def funcs_to_strings():
    ret = []
    for func in eqi_funcs:
        ret.append(func_to_string(func))
    return ret

def http_to_file(url, path):
    request = r.urlopen(url)
    content = request.read()
    file = open(path, "wb")
    file.write(content)
    file.close()

def http_to_string(url):
    request = r.urlopen(url)
    content = request.read()
    return str(content)[2:-1]

def arr2d_to_csv(data, filepath, column_labels, row_labels):
    file = open(filepath, "w")
    file.write("\"\"")
    for label in column_labels:
        file.write(",\"" + label + "\"")
    for row in range(len(row_labels)):
        file.write("\n\"" + row_labels[row] + "\"")
        for column in range(len(column_labels)):
            file.write("," + str(data[row][column]))
    file.close()

main()
