package apdu

// CheckOK checks the error and response from an APDU operation.
// If err is non-nil it is returned. Otherwise it checks that resp.Sw
// matches one of the allowed status words (defaults to SwOK).
func CheckOK(resp *Response, err error, allowedResponses ...uint16) error {
	if err != nil {
		return err
	}
	if len(allowedResponses) == 0 {
		allowedResponses = []uint16{SwOK}
	}
	for _, code := range allowedResponses {
		if code == resp.Sw {
			return nil
		}
	}
	return NewErrBadResponse(resp.Sw, "unexpected response")
}
