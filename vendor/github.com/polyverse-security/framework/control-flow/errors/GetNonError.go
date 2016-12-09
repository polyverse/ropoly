package errors

import (
	log "github.com/Sirupsen/logrus"
)

//Use as a monadic compositional pattern. Exit when error, else return string without the error
func GetNonErrorPanic(val interface{}, err error) interface{} {
	return GetNonErrorPanicWithMessage(val, err, "An error occurred. Unable to ignore it. Panicking out of the program.")
}

//Use as a monadic compositional pattern. Exit when error, else return string without the error
func GetNonErrorIgnore(val interface{}, err error) interface{} {
	return GetNonErrorIgnoreWithMessage(val, err, "An error occurred. Ignoring it and moving on.")
}

//Use as a monadic compositional pattern. Exit when error, else return string without the error
func GetNonErrorPanicWithMessage(val interface{}, err error, message string) interface{} {
	if err != nil {
		log.WithField("Error", err).Panic(message)
	}
	return val
}

//Use as a monadic compositional pattern. Exit when error, else return string without the error
func GetNonErrorIgnoreWithMessage(val interface{}, err error, message string) interface{} {
	if err != nil {
		log.WithField("Error", err).Error(message)
	}
	return val
}
