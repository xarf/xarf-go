package xarf

import "fmt"

// XARFError represents a base XARF error
type XARFError struct {
	Message string
	Err     error
}

func (e *XARFError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *XARFError) Unwrap() error {
	return e.Err
}

// ParseError represents a parsing error
type ParseError struct {
	Message string
	Err     error
}

// NewParseError creates a new ParseError
func NewParseError(message string, err error) *ParseError {
	return &ParseError{
		Message: message,
		Err:     err,
	}
}

func (e *ParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *ParseError) Unwrap() error {
	return e.Err
}

// ValidationError represents a validation error
type ValidationError struct {
	Message string
	Errors  []string
}

// NewValidationError creates a new ValidationError
func NewValidationError(message string, errors []string) *ValidationError {
	return &ValidationError{
		Message: message,
		Errors:  errors,
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
	Message string
	Err     error
}

// NewGeneratorError creates a new GeneratorError
func NewGeneratorError(message string, err error) *GeneratorError {
	return &GeneratorError{
		Message: message,
		Err:     err,
	}
}

func (e *GeneratorError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *GeneratorError) Unwrap() error {
	return e.Err
}
