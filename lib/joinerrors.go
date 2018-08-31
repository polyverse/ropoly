package lib

func joinerrors(arrayOfErrors ...[]error) []error {
	errors := []error{}
	for _, errorsElem := range arrayOfErrors {
		errors = append(errors, errorsElem...)
	}
	return errors
}
