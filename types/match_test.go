// Copyright 2018 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
)

func TestMatcherValidate(t *testing.T) {

	validLabelName := "valid_label_name"
	validStringValue := "value"
	validRegexValue := ".*"

	invalidLabelName := "123_invalid_name"
	invalidStringValue := ""
	invalidRegexValue := "]*.["

	tests := []struct {
		matcher  Matcher
		valid    bool
		errorMsg string
	}{
		//valid tests
		{
			matcher: Matcher{Name: validLabelName, Value: validStringValue},
			valid:   true,
		},
		{
			matcher: Matcher{Name: validLabelName, Value: validRegexValue, IsRegex: true},
			valid:   true,
		},
		// invalid tests
		{
			matcher:  Matcher{Name: invalidLabelName, Value: validStringValue},
			valid:    false,
			errorMsg: fmt.Sprintf("invalid name %q", invalidLabelName),
		},
		{
			matcher:  Matcher{Name: validLabelName, Value: invalidStringValue},
			valid:    false,
			errorMsg: fmt.Sprintf("invalid value %q", invalidStringValue),
		},
		{
			matcher:  Matcher{Name: validLabelName, Value: invalidRegexValue, IsRegex: true},
			valid:    false,
			errorMsg: fmt.Sprintf("invalid regular expression %q", invalidRegexValue),
		},
	}

	for _, test := range tests {
		test.matcher.Init()

		if test.valid {
			require.NoError(t, test.matcher.Validate())
			continue
		}

		require.EqualError(t, test.matcher.Validate(), test.errorMsg)
	}
}

func TestMatcherInit(t *testing.T) {
	m := Matcher{Name: "label", Value: ".*", IsRegex: true}
	require.NoError(t, m.Init())
	require.EqualValues(t, "^(?:.*)$", m.regex.String())

	m = Matcher{Name: "label", Value: "]*.[", IsRegex: true}
	require.Error(t, m.Init())
}

func TestMatcherMatch(t *testing.T) {
	tests := []struct {
		matcher  Matcher
		expected bool
	}{
		{matcher: Matcher{Name: "label", Value: "value"}, expected: true},
		{matcher: Matcher{Name: "label", Value: "val"}, expected: false},
		{matcher: Matcher{Name: "label", Value: "val.*", IsRegex: true}, expected: true},
		{matcher: Matcher{Name: "label", Value: "diffval.*", IsRegex: true}, expected: false},
		//unset label
		{matcher: Matcher{Name: "difflabel", Value: "value"}, expected: false},
	}

	lset := model.LabelSet{"label": "value"}
	for _, test := range tests {
		test.matcher.Init()

		actual := test.matcher.Match(lset)
		require.EqualValues(t, test.expected, actual)
	}
}

func TestMatcherString(t *testing.T) {
	m := NewMatcher("foo", "bar")

	if m.String() != "foo=\"bar\"" {
		t.Errorf("unexpected matcher string %#v", m.String())
	}

	re, err := regexp.Compile(".*")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	m = NewRegexMatcher("foo", re)

	if m.String() != "foo=~\".*\"" {
		t.Errorf("unexpected matcher string %#v", m.String())
	}
}

func TestMatchersString(t *testing.T) {
	m1 := NewMatcher("foo", "bar")

	re, err := regexp.Compile(".*")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	m2 := NewRegexMatcher("bar", re)

	matchers := NewMatchers(m1, m2)

	if matchers.String() != "{bar=~\".*\",foo=\"bar\"}" {
		t.Errorf("unexpected matcher string %#v", matchers.String())
	}
}

func TestMatchersSort(t *testing.T) {
	type input struct {
		name  string
		value string
		regex bool
	}

	cases := []struct {
		name   string
		i1, i2 input
		expect Matchers
	}{
		{
			name:   "name asc order",
			i1:     input{name: "foo", value: "bar"},
			i2:     input{name: "goo", value: "bar"},
			expect: Matchers{&Matcher{Name: "foo", Value: "bar"}, &Matcher{Name: "goo", Value: "bar"}},
		},
		{
			name:   "name desc order",
			i1:     input{name: "foo", value: "bar"},
			i2:     input{name: "doo", value: "bar"},
			expect: Matchers{&Matcher{Name: "doo", Value: "bar"}, &Matcher{Name: "foo", Value: "bar"}},
		},
		{
			name:   "name equal",
			i1:     input{name: "foo", value: "bar"},
			i2:     input{name: "foo", value: "bar"},
			expect: Matchers{&Matcher{Name: "foo", Value: "bar"}, &Matcher{Name: "foo", Value: "bar"}},
		},
		{
			name:   "type asc order",
			i1:     input{name: "foo", value: "bar"},
			i2:     input{name: "foo", value: "car"},
			expect: Matchers{&Matcher{Name: "foo", Value: "bar"}, &Matcher{Name: "foo", Value: "car"}},
		},
		{
			name:   "type desc order",
			i1:     input{name: "foo", value: "bar"},
			i2:     input{name: "foo", value: "aar"},
			expect: Matchers{&Matcher{Name: "foo", Value: "aar"}, &Matcher{Name: "foo", Value: "bar"}},
		},
		{
			name:   "regexp and no regexp",
			i1:     input{name: "foo", value: "bar"},
			i2:     input{name: "foo", value: "bar", regex: true},
			expect: Matchers{&Matcher{Name: "foo", Value: "bar"}, &Matcher{Name: "foo", Value: "bar", IsRegex: true}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m1 := &Matcher{Name: c.i1.name, Value: c.i1.value, IsRegex: c.i1.regex}
			m1.Init()
			m2 := &Matcher{Name: c.i2.name, Value: c.i2.value, IsRegex: c.i2.regex}
			m2.Init()
			got := NewMatchers(m1, m2)
			require.True(t, equalMatchers(c.expect, got))
		})
	}
}

func TestMatchersMatch(t *testing.T) {

	m1 := &Matcher{Name: "label1", Value: "value1"}
	m1.Init()
	m2 := &Matcher{Name: "label2", Value: "val.*", IsRegex: true}
	m2.Init()
	m3 := &Matcher{Name: "label3", Value: "value3"}
	m3.Init()

	tests := []struct {
		matchers Matchers
		expected bool
	}{
		{matchers: Matchers{m1, m2}, expected: true},
		{matchers: Matchers{m1, m3}, expected: false},
	}

	lset := model.LabelSet{"label1": "value1", "label2": "value2"}
	for _, test := range tests {
		actual := test.matchers.Match(lset)
		require.EqualValues(t, test.expected, actual)
	}
}

func TestMatchersEqual(t *testing.T) {

	m1 := &Matcher{Name: "label1", Value: "value1"}
	m1.Init()
	m2 := &Matcher{Name: "label2", Value: "val.*", IsRegex: true}
	m2.Init()
	m3 := &Matcher{Name: "label3", Value: "value3"}
	m3.Init()

	tests := []struct {
		matchers1 Matchers
		matchers2 Matchers
		expected  bool
	}{
		{matchers1: Matchers{m1, m2}, matchers2: Matchers{m1, m2}, expected: true},
		{matchers1: Matchers{m1, m3}, matchers2: Matchers{m1, m2}, expected: false},
	}

	for _, test := range tests {
		actual := equalMatchers(test.matchers1, test.matchers2)
		require.EqualValues(t, test.expected, actual)
	}
}

func equalMatcher(m, n *Matcher) bool {
	return m.Name == n.Name && m.Value == n.Value && m.IsRegex == n.IsRegex
}

func equalMatchers(m, n Matchers) bool {
	if len(m) != len(n) {
		return false
	}
	for i, a := range m {
		if !equalMatcher(a, n[i]) {
			return false
		}
	}
	return true
}
