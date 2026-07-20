package spoa

import (
	"encoding/json"
	"reflect"
	"testing"
)

func Test_toValue(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		raw     json.RawMessage
		want    any
		wantErr bool
	}{
		{
			name: "string value",
			raw:  json.RawMessage(`"thisisastring"`),
			want: "thisisastring",
		},
		{
			name: "empty string value",
			raw:  json.RawMessage(`""`),
			want: "",
		},
		{
			name: "bool true",
			raw:  json.RawMessage(`true`),
			want: true,
		},
		{
			name: "bool false",
			raw:  json.RawMessage(`false`),
			want: false,
		},
		{
			name: "whole number decodes as int",
			raw:  json.RawMessage(`1720000000`),
			want: 1720000000,
		},
		{
			name: "zero decodes as int",
			raw:  json.RawMessage(`0`),
			want: 0,
		},
		{
			name: "negative whole number decodes as int",
			raw:  json.RawMessage(`-42`),
			want: -42,
		},
		{
			name: "non-whole number falls back to string",
			raw:  json.RawMessage(`98.5`),
			want: "98.5",
		},
		{
			name: "null falls back to empty string",
			raw:  json.RawMessage(`null`),
			want: "",
		},
		{
			name: "array falls back to compact JSON string",
			raw:  json.RawMessage(`["admin", "user"]`),
			want: `["admin","user"]`,
		},
		{
			name: "object falls back to compact JSON string",
			raw:  json.RawMessage(`{"foo": "bar"}`),
			want: `{"foo":"bar"}`,
		},
		{
			name: "empty array falls back to compact JSON string",
			raw:  json.RawMessage(`[]`),
			want: `[]`,
		},
		{
			name:    "invalid JSON returns error",
			raw:     json.RawMessage(`{invalid`),
			wantErr: true,
		},
		{
			name:    "empty raw message returns error",
			raw:     json.RawMessage(``),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := toValue(tt.raw)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("toValue() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("toValue() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toValue() = %v (%T), want %v (%T)", got, got, tt.want, tt.want)
			}
		})
	}
}
