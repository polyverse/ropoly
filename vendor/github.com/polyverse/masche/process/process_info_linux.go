package process

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

type linuxProcessInfo struct {
	Id              int    `json:"id" statusFileKey:"Pid"`
	Command         string `json:"command" statusFileKey:"Name"`
	UserId          int    `json:"userId" statusFileKey:"Uid"`
	UserName        string `json:"userName" statusFileKey:""`
	GroupId         int    `json:"groupId" statusFileKey:"Gid"`
	GroupName       string `json:"groupName" statusFileKey:""`
	ParentProcessId int    `json:"parentProcessId" statusFileKey:"PPid"`
	Executable      string `json:"executable"`
}

func (lpi linuxProcessInfo) GetId() int {
	return lpi.Id
}

func (lpi linuxProcessInfo) GetCommand() string {
	return lpi.Command
}

func (lpi linuxProcessInfo) GetParentProcessId() int {
	return lpi.ParentProcessId
}

func (lpi linuxProcessInfo) GetExecutable() string {
	return lpi.Executable
}

var (
	tmpLpi         = linuxProcessInfo{}
	keyToFieldName = map[string]string{}
	mtx            = &sync.RWMutex{}
)

func processInfo(pid int) (linuxProcessInfo, error) {
	statusPath := filepath.Join("/proc", fmt.Sprintf("%d", pid), "status")
	statusFile, err := os.Open(statusPath)
	if err != nil {
		return linuxProcessInfo{}, fmt.Errorf("Unable to open proc %d's status file at %s (%v)", pid, statusPath, err)
	}
	defer statusFile.Close()

	data, err := ioutil.ReadAll(statusFile)
	if err != nil {
		return linuxProcessInfo{}, fmt.Errorf("Unable to read data from proc %d's status file at %s (%v)", pid, statusPath, err)
	}

	lpi := linuxProcessInfo{}
	err = parseStatusToStruct(data, &lpi)
	if err != nil {
		return linuxProcessInfo{}, fmt.Errorf("Unable to process data from %s into linuxProcessInfo struct (%v)", statusPath, err)
	}

	//we ignore this error
	lpi.Executable, err = ProcessExe(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Warning] Error when expanding symlink to executable: %v\n", err)
	}

	return lpi, err
}

func processExe(pid int) (string, error) {
	exePath := filepath.Join("/proc", fmt.Sprintf("%d", pid), "exe")
	name, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", fmt.Errorf("Unable to expand process executable symlink %s (%v)", exePath, err)
	}
	return name, nil
}

func parseStatusToStruct(data []byte, lpi *linuxProcessInfo) error {
	if lpi == nil {
		return fmt.Errorf("Cannot parse Process Status into a nil linuxProcessInfo")
	}

	r := bufio.NewReader(bytes.NewReader(data))
	for line, err := r.ReadString('\n'); err != io.EOF; line, err = r.ReadString('\n') {
		if err != nil {
			return fmt.Errorf("Error when parsing Status line from Proc Status data (%v)", err)
		}

		statusComponents := strings.Split(line, ":")
		if len(statusComponents) != 2 {
			continue
		}

		key := strings.TrimSpace(statusComponents[0])
		value := strings.TrimSpace(statusComponents[1])

		vals := strings.Fields(value)
		if len(vals) > 0 {
			value = vals[0]
		}

		fieldName := getFieldNameForKey(key)
		vfield := reflect.ValueOf(lpi).Elem().FieldByName(fieldName)
		if !vfield.IsValid() {
			continue //Nobody wants this value
		}

		val, err := stringToReflectValue(value, vfield.Type())
		if err != nil {
			return err
		}

		vfield.Set(val)
	}
	return nil
}

func stringToReflectValue(value string, t reflect.Type) (reflect.Value, error) {
	switch t.Name() {
	case "string":
		return reflect.ValueOf(value), nil
	case "int":
		intVal, err := strconv.Atoi(value)
		if err != nil {
			return reflect.Value{}, fmt.Errorf("Error converting string %s into an integer. (%v)", value, err)
		}
		return reflect.ValueOf(intVal), nil
	}
	return reflect.Value{}, fmt.Errorf("Unsupported Converstion: string %s to value of type %v", value, t)
}

func getFieldNameForKey(key string) string {
	mtx.RLock()
	fieldName, ok := keyToFieldName[key]
	mtx.RUnlock()
	if ok {
		return fieldName
	}

	t := reflect.TypeOf(tmpLpi)
	fieldForKey, found := t.FieldByNameFunc(func(name string) bool {
		fieldCandidate, found := t.FieldByName(name)
		if found && fieldCandidate.Tag.Get("statusFileKey") == key {
			return true
		}
		return false
	})

	if !found {
		return ""
	}

	mtx.Lock()
	defer mtx.Unlock()
	keyToFieldName[key] = fieldForKey.Name
	return keyToFieldName[key]
}

func appendError(errs []error, err error, format string, params ...interface{}) []error {
	if err == nil {
		return errs
	}

	params = append(params, err)
	wrappedErr := fmt.Errorf(format+" (%v)", params...)
	errs = append(errs, wrappedErr)
	return errs
}
