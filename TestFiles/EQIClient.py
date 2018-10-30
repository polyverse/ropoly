# Set go_parent_dir to the folder that your installation of go is in.
# Clone ropoly into go/src/github.com/polyverse/ropoly.
go_parent_dir = "/usr/local"

# Set binary_pairs to the pairs of binaries to generate EQIs, original first and modified second.
# Each pair of binaries must be in ropoly/TestFiles.
# binary_pairs needs to have at least two items or Python freaks out.
# If you only want to test one pair, use a None for the second.
binary_pairs = (("loop_o0", "loop_o1"), None)

# Set eqi_funcs to the list of EQI functions you want to use.
# Name of function first, followed by list of arguments.
eqi_funcs = (["envisen-original", {}],
             ["monte-carlo", {"min":2, "max":10, "trials":1000000}])

function = 0
arguments = 1
relative_directory = "TestFiles/"
server_absolute_directory = "/go/src/github.com/polyverse/ropoly/" + relative_directory
client_absolute_directory = go_parent_dir + server_absolute_directory
url_prefix = "http://localhost:8008/api/v1/"
fingerprint_suffix = "_f"

import urllib.request as r
import json

def main():
    for pair in binary_pairs:
        if pair != None:
            for i in range(2):
                fingerprint_url = url_prefix + "files" + server_absolute_directory + pair[i] + "?mode=fingerprint"
                http_to_file(fingerprint_url, client_absolute_directory + pair[i] + fingerprint_suffix)

            comparison_url = url_prefix + "compare?old=" + relative_directory + pair[0] + fingerprint_suffix \
                             + "&new=" + relative_directory + pair[1] + fingerprint_suffix
            comparison_file = pair[0] + "__" + pair[1]
            http_to_file(comparison_url, client_absolute_directory + comparison_file)

            region_map = int_mapper()
            eqis = []
            for func in eqi_funcs:
                func_eqis = expanding_slice("")
                
                eqi_url = url_prefix + "eqi?comparison=" + relative_directory + comparison_file + "&func=" + func_to_string(func)
                
                eqi_struct = http_to_struct(eqi_url)
                for eqi_region in eqi_struct["region EQIs"]:
                    region = eqi_region["region"]["kind"]
                    region_index = region_map[region]
                    eqi = eqi_region["EQI"]
                    func_eqis[region_index] = eqi
                eqis.append(func_eqis)

            csv_file = client_absolute_directory + comparison_file + ".csv"
            arr2d_to_csv(eqis, csv_file, region_map.ordered_keys(), funcs_to_strings())

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

def http_to_struct(url):
    request = r.urlopen(url)
    content = request.read()
    struct = json.loads(content)
    return struct

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

class int_mapper:
    next_value = None
    mapping = None

    def __init__(self):
        self.next_value = 0
        self.mapping = {}

    def __getitem__(self, index):
        if index not in self.mapping:
            self.mapping[index] = self.next_value
            self.next_value += 1
        return self.mapping[index]

    def ordered_keys(self):
        return self.mapping.keys()

class expanding_slice:
    values = None
    fill = None

    def __init__(self, fill):
        self.values = []
        self.fill = fill

    def __getitem__(self, index):
        if index >= len(self.values):
            return self.fill
        else:
            return self.values[index]

    def __setitem__(self, index, value):
        while index >= len(self.values):
            self.values.append(self.fill)
        self.values[index] = value

main()
