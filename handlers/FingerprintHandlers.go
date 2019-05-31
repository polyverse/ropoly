package handlers

import (
	"bytes"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/gorilla/mux"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
	"github.com/polyverse/ropoly/lib"
	"github.com/polyverse/ropoly/lib/architectures"
	"github.com/polyverse/ropoly/lib/gadgets"
	"github.com/polyverse/ropoly/lib/types"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
)

func FingerprintForFileHandler(w http.ResponseWriter, r *http.Request, path string) {
	fingerprintHandler(w, r, true, 0, path)
}

func FingerprintForPidHandler(w http.ResponseWriter, r *http.Request, pid int) {
	fingerprintHandler(w, r, false, pid, "")
}

func fingerprintHandler(w http.ResponseWriter, r *http.Request, isFile bool, pid int, path string) {
	var gadgetLen uint64 = 2 // Gadgets longer than 2 instructions must be requested explicitly
	var err error
	lenStr := r.Form.Get("len")
	if lenStr != "" {
		gadgetLen, err = strconv.ParseUint(lenStr, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} // if
	} // else if

	var start uint64 = defaultStart
	startStr := r.Form.Get("start")
	if startStr != "" {
		start, err = strconv.ParseUint(startStr, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} // if
	} // else if

	var end uint64 = defaultEnd
	endStr := r.Form.Get("end")
	if endStr != "" {
		end, err = strconv.ParseUint(endStr, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} // if
	} // else if

	var base uint64 = defaultStart
	baseStr := r.Form.Get("base")
	if baseStr != "" {
		base, err = strconv.ParseUint(baseStr, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} // if
	} // else if

	outputFile := r.Form.Get("out")

	var gadgets types.GadgetInstances
	var softerrors []error
	if isFile {
		gadgets, err, softerrors = lib.GadgetsFromFile(path, int(gadgetLen))
	} else {
		gadgets, err, softerrors = lib.GadgetsFromProcess(pid, int(gadgetLen),
			types.Addr(start), types.Addr(end), types.Addr(base))
	}
	if err != nil {
		logErrors(err, softerrors)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fingerprint, err := types.FingerprintFromGadgets(gadgets)
	if err != nil {
		logErrors(err, softerrors)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.MarshalIndent(fingerprint, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if outputFile == "" {
		w.Write(b)
	} else {
		if DataDirectory == "" {
			err := errors.New("Requested to save file, but persistent data directory not set.")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			logErrors(err, nil)
			return
		}

		filepath := FingerprintsDirectory() + outputFile

		if r.Form.Get("overwrite") != "true" {
			exists, err := lib.Exists(filepath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				logErrors(err, nil)
				return
			}
			if exists {
				b := []byte("File already exists. Use \"overwrite=true\" to overwrite.")
				w.Write(b)
				return
			}
		}

		err := ioutil.WriteFile(FingerprintsDirectory()+outputFile, b, 0666)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			logErrors(err, nil)
			return
		}
	}
}

func RegionFingerprintsHandler(w http.ResponseWriter, r *http.Request, pid int) {
	providedName := r.Form.Get("out")

	var maxLength uint64 = 2 // Gadgets longer than 2 instructions must be requested explicitly
	lenStr := r.Form.Get("len")
	var err error
	if lenStr != "" {
		maxLength, err = strconv.ParseUint(lenStr, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} // if
	} // else if

	var architecture architectures.Architecture = architectures.X86
	architectureStr := r.Form.Get("architecture")
	if architectureStr != "" {
		architecture = architectures.ArchitecturesByName[architectureStr]
	} // if

	softerrors := []error{}
	proc := process.GetProcess(int(pid))

	createdFingerprints := []string{}

	pc := uintptr(0)
	for {
		region, harderror2, softerrors2 := memaccess.NextMemoryRegionAccess(proc, uintptr(pc), memaccess.Readable+memaccess.Executable)
		softerrors = append(softerrors, softerrors2...)
		if harderror2 != nil {
			logErrors(harderror2, softerrors)
			err := errors.Wrapf(harderror2, "Error when attempting to access the next memory region for Pid %d.", pid)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if region == memaccess.NoRegionAvailable {
			break
		}

		//Make sure we move the Program Counter
		pc = region.Address + uintptr(region.Size)

		opcodes := make([]byte, region.Size, region.Size)
		harderr3, softerrors3 := memaccess.CopyMemory(proc, region.Address, opcodes)
		softerrors = append(softerrors, softerrors3...)
		if harderr3 != nil {
			softerrors = append(softerrors, errors.Wrapf(harderr3, "Error when attempting to access the memory contents for Pid %d.", pid))
		}

		foundgadgets, harderr4, softerrors4 := gadgets.Find(opcodes, architectures.GadgetSpecLists[architecture], architectures.GadgetDecoderFuncs[architecture], types.Addr(region.Address), int(maxLength))
		softerrors = append(softerrors, softerrors4...)
		if harderr4 != nil {
			logErrors(harderr4, softerrors)
			err := errors.Wrapf(harderr4, "Error when attempting to decode gadgets from the memory region %s for Pid %d.", region.String(), pid)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fingerprintName := providedName +  "__0x" + strconv.FormatUint(uint64(region.Address), 16) +
			"__to__0x" + strconv.FormatUint(uint64(region.Address) + uint64(region.Size), 16)
		fingerprint, harderr5 := types.FingerprintFromGadgets(foundgadgets)
		if harderr5 != nil {
			logErrors(harderr5, softerrors)
			err := errors.Wrapf(harderr5, "Error creating fingerprint gadget mapping")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		b, err := json.MarshalIndent(fingerprint, "", indent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if DataDirectory == "" {
			err := errors.New("Requested to save file, but persistent data directory not set.")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			logErrors(err, nil)
			return
		}

		filepath := FingerprintsDirectory() + fingerprintName

		if r.Form.Get("overwrite") != "true" {
			exists, err := lib.Exists(filepath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				logErrors(err, nil)
				return
			}
			if exists {
				b := []byte("File already exists. Use \"overwrite=true\" to overwrite.")
				w.Write(b)
				return
			}
		}

		err = ioutil.WriteFile(filepath, b, 0666)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			logErrors(err, nil)
			return
		}

		createdFingerprints = append(createdFingerprints, fingerprintName + " (" + region.Kind + ")")
	}

	b1 := []byte("Created fingerprints:\n")
	b2, err := json.MarshalIndent(createdFingerprints, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(append(b1, b2...))
}

func FingerprintFormatHandler(w http.ResponseWriter, r *http.Request) {
	fingerprintName := mux.Vars(r)["fingerprint"]
	path := NormalizePath(FingerprintsDirectory() + fingerprintName)
	b, err := ioutil.ReadFile(path)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var fingerprint types.Fingerprint
	err = json.Unmarshal(b, &fingerprint)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	b, err = json.MarshalIndent(fingerprint, "", indent)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = ioutil.WriteFile(path, b, 0666)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func FingerprintListingHandler(w http.ResponseWriter, r *http.Request) {
	if DataDirectory == "" {
		err := errors.New("Persistent data directory not provided.")
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fingerprintFiles, err := ioutil.ReadDir(FingerprintsDirectory())
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fingerprints := make([]string, len(fingerprintFiles))
	for i := 0; i < len(fingerprintFiles); i++ {
		fingerprints[i] = fingerprintFiles[i].Name()
	}

	b, err := json.MarshalIndent(fingerprints, "", indent)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(b)
}

func StoredFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	fingerprint := mux.Vars(r)["fingerprint"]
	b, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + fingerprint))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

func PostFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["fingerprint"]
	path := NormalizePath(FingerprintsDirectory() + name)

	if r.FormValue("overwrite") != "true" {
		exists, err := lib.Exists(path)
		if err != nil {
			logErrors(err, nil)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if exists {
			b := []byte("File already exists. Use \"overwrite=true\" to overwrite.")
			w.Write(b)
			return
		}
	}

	file, _, err := r.FormFile("fingerprint")
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var b bytes.Buffer
	io.Copy(&b, file)
	ioutil.WriteFile(path, b.Bytes(), 0666)
}

func StoredFingerprintEqiHandler(w http.ResponseWriter, r *http.Request) {
	f1Name := mux.Vars(r)["fingerprint"]
	f2Name := r.FormValue("second")
	eqiFunc := r.Form.Get("func")

	f1Bytes, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + f1Name))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	f2Bytes, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + f2Name))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var f1 types.Fingerprint
	err = json.Unmarshal(f1Bytes, &f1)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var f2 types.Fingerprint
	err = json.Unmarshal(f2Bytes, &f2)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	eqi, err := lib.DirectEqi(f1, f2, eqiFunc, r.Form)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.MarshalIndent(eqi, "", indent)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

func StoredFingerprintSurvivalHandler(w http.ResponseWriter, r *http.Request) {
	f1Name := mux.Vars(r)["fingerprint"]
	f2Name := r.FormValue("second")

	f1Bytes, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + f1Name))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	f2Bytes, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + f2Name))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var f1 types.Fingerprint
	err = json.Unmarshal(f1Bytes, &f1)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var f2 types.Fingerprint
	err = json.Unmarshal(f2Bytes, &f2)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	original := lib.GadgetCount(f1)
	survived := lib.GadgetSurvival(f1, f2)
	outStr := strconv.FormatUint(uint64(survived), 10) + " out of " + strconv.FormatUint(uint64(original), 10)

	b := []byte(outStr)
	w.Write(b)
}

func StoredFingerprintKillRateHandler(w http.ResponseWriter, r *http.Request) {
	f1Name := mux.Vars(r)["fingerprint"]
	f2Name := r.FormValue("second")

	f1Bytes, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + f1Name))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	f2Bytes, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + f2Name))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var f1 types.Fingerprint
	err = json.Unmarshal(f1Bytes, &f1)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var f2 types.Fingerprint
	err = json.Unmarshal(f2Bytes, &f2)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	original := lib.GadgetCount(f1)
	survived := lib.GadgetSurvival(f1, f2)
	killRate := float64(original - survived) / float64(original)
	killRateStr := strconv.FormatFloat(killRate, 'f', -1, 64)

	b := []byte(killRateStr)
	w.Write(b)
}

func StoredFingerprintHighestOffsetCountHandler(w http.ResponseWriter, r *http.Request) {
	f1Name := mux.Vars(r)["fingerprint"]
	f2Name := r.FormValue("second")

	f1Bytes, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + f1Name))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	f2Bytes, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + f2Name))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var f1 types.Fingerprint
	err = json.Unmarshal(f1Bytes, &f1)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var f2 types.Fingerprint
	err = json.Unmarshal(f2Bytes, &f2)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	original := lib.GadgetCount(f1)
	highestOffsetCount, highestOffset := lib.HighestOffsetCount(f1, f2)
	pseudoKillrate := float64(1) - (float64(highestOffsetCount) / float64(original))

	outStr := strconv.FormatUint(uint64(highestOffsetCount), 10) + " out of " +
		strconv.FormatUint(uint64(original), 10) + " at offset 0x" + strconv.FormatInt(int64(highestOffset), 16) +
		" (\"killrate\": " + strconv.FormatFloat(pseudoKillrate, 'G', 6, 64) + ")"
	b := []byte(outStr)
	w.Write(b)
}

func StoredFingerprintGadgetCountHandler(w http.ResponseWriter, r *http.Request) {
	fName := mux.Vars(r)["fingerprint"]

	fBytes, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + fName))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var f types.Fingerprint
	err = json.Unmarshal(fBytes, &f)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	count := lib.GadgetCount(f)
	outStr := strconv.FormatUint(uint64(count), 10)
	b := []byte(outStr)
	w.Write(b)
}

func StoredFingerprintComparisonHandler(w http.ResponseWriter, r *http.Request) {
	f1Name := mux.Vars(r)["fingerprint"]
	f2Name := r.FormValue("second")
	includeSurvived := r.FormValue("include-survived") != "false"

	f1Bytes, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + f1Name))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	f2Bytes, err := ioutil.ReadFile(NormalizePath(FingerprintsDirectory() + f2Name))
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var f1 types.Fingerprint
	err = json.Unmarshal(f1Bytes, &f1)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var f2 types.Fingerprint
	err = json.Unmarshal(f2Bytes, &f2)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	comparison := lib.CompareFingerprints(f1, f2, includeSurvived)
	b, err := json.MarshalIndent(comparison, "", indent)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(b)
}
