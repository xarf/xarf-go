package xarf

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestXARFErrorError(t *testing.T) {
	tests := []struct {
		name     string
		err      *XARFError
		expected string
	}{
		{
			name: "With underlying error",
			err: &XARFError{
				Message: "test error",
				Err:     errors.New("underlying"),
			},
			expected: "test error: underlying",
		},
		{
			name: "Without underlying error",
			err: &XARFError{
				Message: "test error",
			},
			expected: "test error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestXARFErrorUnwrap(t *testing.T) {
	underlyingErr := errors.New("underlying")
	err := &XARFError{
		Message: "test",
		Err:     underlyingErr,
	}

	assert.Equal(t, underlyingErr, err.Unwrap())

	errWithoutUnderlying := &XARFError{Message: "test"}
	assert.Nil(t, errWithoutUnderlying.Unwrap())
}

func TestParseErrorError(t *testing.T) {
	tests := []struct {
		name     string
		err      *ParseError
		expected string
	}{
		{
			name: "With underlying error",
			err: &ParseError{
				Message: "parse failed",
				Err:     errors.New("json error"),
			},
			expected: "parse failed: json error",
		},
		{
			name: "Without underlying error",
			err: &ParseError{
				Message: "parse failed",
			},
			expected: "parse failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestParseErrorUnwrap(t *testing.T) {
	underlyingErr := errors.New("underlying")
	err := NewParseError("test", underlyingErr)

	assert.Equal(t, underlyingErr, err.Unwrap())

	errWithoutUnderlying := NewParseError("test", nil)
	assert.Nil(t, errWithoutUnderlying.Unwrap())
}

func TestValidationErrorError(t *testing.T) {
	tests := []struct {
		name     string
		err      *ValidationError
		expected string
	}{
		{
			name: "With validation errors",
			err: &ValidationError{
				Message: "validation failed",
				Errors:  []string{"error1", "error2"},
			},
			expected: "validation failed: [error1 error2]",
		},
		{
			name: "Without validation errors",
			err: &ValidationError{
				Message: "validation failed",
				Errors:  []string{},
			},
			expected: "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestGeneratorErrorError(t *testing.T) {
	tests := []struct {
		name     string
		err      *GeneratorError
		expected string
	}{
		{
			name: "With underlying error",
			err: &GeneratorError{
				Message: "generation failed",
				Err:     errors.New("hash error"),
			},
			expected: "generation failed: hash error",
		},
		{
			name: "Without underlying error",
			err: &GeneratorError{
				Message: "generation failed",
			},
			expected: "generation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestGeneratorErrorUnwrap(t *testing.T) {
	underlyingErr := errors.New("underlying")
	err := NewGeneratorError("test", underlyingErr)

	assert.Equal(t, underlyingErr, err.Unwrap())

	errWithoutUnderlying := NewGeneratorError("test", nil)
	assert.Nil(t, errWithoutUnderlying.Unwrap())
}
