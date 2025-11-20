package xarf

import "fmt"

// Error represents a XARF error
type Error struct {
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *Error) Unwrap() error {
	return e.Err
}

// ParseError represents a parsing error
type ParseError struct {
	*Error
}

// NewParseError creates a new ParseError
func NewParseError(message string, err error) *ParseError {
	return &ParseError{
		Error: &Error{
			Message: message,
			Err:     err,
		},
	}
}

// ValidationError represents a validation error
type ValidationError struct {
	*Error
	Errors []string
}

// NewValidationError creates a new ValidationError
func NewValidationError(message string, errors []string) *ValidationError {
	return &ValidationError{
		Error: &Error{
			Message: message,
		},
		Errors: errors,
	}
}

func (e *ValidationError) Error() string {
	if len(e.Errors) == 0 {
		return e.Message
	}
	return fmt.Sprintf("%s: %v", e.Message, e.Errors)
}

// GeneratorError represents a generator error
type GeneratorError struct {
	*Error
}

// NewGeneratorError creates a new GeneratorError
func NewGeneratorError(message string, err error) *GeneratorError {
	return &GeneratorError{
		Error: &Error{
			Message: message,
			Err:     err,
		},
	}
}
