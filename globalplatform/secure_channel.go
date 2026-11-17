package globalplatform

import (
	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/hexutils"
	"github.com/keycard-tech/keycard-go/v4/types"
)

// secureMessagingWrapper protects the commands of a secure channel and removes the
// protection of the responses.
type secureMessagingWrapper interface {
	Wrap(cmd *apdu.Command) (*apdu.Command, error)
	WrapAuthenticate(cmd *apdu.Command) (*apdu.Command, error)
	Unwrap(resp *apdu.Response) (*apdu.Response, error)
	maxDataSize() int
}

// SecureChannel wraps another channel and sends its commands protected by the secure
// messaging of the session it was opened with.
type SecureChannel struct {
	c types.Channel
	w secureMessagingWrapper
}

// NewSecureChannel returns a new SecureChannel for a session, sending on channel c.
func NewSecureChannel(session *Session, c types.Channel) (*SecureChannel, error) {
	w, err := session.newWrapper()
	if err != nil {
		return nil, err
	}

	return &SecureChannel{
		c: c,
		w: w,
	}, nil
}

// Send sends wrapped commands to the inner channel and returns the unprotected response.
func (c *SecureChannel) Send(cmd *apdu.Command) (*apdu.Response, error) {
	rawCmd, err := cmd.Serialize()
	if err != nil {
		return nil, err
	}

	logger.Debug("wrapping apdu command", "hex", hexutils.BytesToHexWithSpaces(rawCmd))
	wrappedCmd, err := c.w.Wrap(cmd)
	if err != nil {
		return nil, err
	}

	resp, err := c.c.Send(wrappedCmd)
	if err != nil {
		return nil, err
	}

	return c.w.Unwrap(resp)
}

// SendAuthenticate sends the command that establishes the secure channel. Its response
// carries no response protection, so it is not unwrapped.
func (c *SecureChannel) SendAuthenticate(cmd *apdu.Command) (*apdu.Response, error) {
	wrappedCmd, err := c.w.WrapAuthenticate(cmd)
	if err != nil {
		return nil, err
	}

	return c.c.Send(wrappedCmd)
}

// MaxCommandData returns the largest command data field that fits in a short apdu once
// the protection of the session is applied.
func (c *SecureChannel) MaxCommandData() int {
	return c.w.maxDataSize()
}
