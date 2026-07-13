package keycard

import (
	"fmt"

	"github.com/status-im/keycard-go/apdu"
)

// ============================================================================
// Status word constants
// ============================================================================

const (
	SwSecurityConditionNotSatisfied uint16 = 0x6982
	SwAuthenticationMethodBlocked   uint16 = 0x6983
	SwCardLocked                    uint16 = 0x6283
	SwReferencedDataNotFound        uint16 = 0x6A88
	SwConditionsOfUseNotSatisfied   uint16 = 0x6985
	SwWrongPINMask                  uint16 = 0x63C0
)

// ============================================================================
// APDUError
// ============================================================================

// APDUError represents an APDU-level error with a status word.
type APDUError struct {
	SW      uint16
	Message string
}

// Error implements the error interface.
func (e *APDUError) Error() string {
	return fmt.Sprintf("APDU error 0x%04X: %s", e.SW, e.Message)
}

// SecurityConditionNotSatisfied returns an APDUError for the security condition
// not satisfied status word.
func SecurityConditionNotSatisfied(sw uint16) *APDUError {
	return &APDUError{
		SW:      sw,
		Message: "Security condition not satisfied",
	}
}

// AuthenticationMethodBlocked returns an APDUError for the authentication method
// blocked status word.
func AuthenticationMethodBlocked(sw uint16) *APDUError {
	return &APDUError{
		SW:      sw,
		Message: "Authentication method blocked",
	}
}

// UnexpectedSW returns an APDUError for an unexpected status word.
func UnexpectedSW(sw uint16, message string) *APDUError {
	return &APDUError{
		SW:      sw,
		Message: message,
	}
}

// ============================================================================
// Helper function to check auth response
// ============================================================================

// CheckAuthOK checks the response status word, handling the 0x63Cx PIN retry
// mask to return a WrongPINError with the remaining attempt count.
func CheckAuthOK(resp *apdu.Response) error {
	if resp == nil {
		return nil
	}
	if resp.Sw == apdu.SwOK {
		return nil
	}
	if (resp.Sw & 0xFF00) == SwWrongPINMask {
		remaining := resp.Sw & 0x000F
		return &WrongPINError{
			RemainingAttempts: int(remaining),
		}
	}
	return apdu.NewErrBadResponse(resp.Sw, "authentication failed")
}
