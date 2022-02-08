// Copyright 2015 Prometheus Team
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

package dispatch

import (
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/prometheus/alertmanager/config"
)

func TestRouteMatch(t *testing.T) {
	in := `
receiver: 'notify-def'

routes:
- match:
    owner: 'team-A'

  receiver: 'notify-A'

  routes:
  - match:
      env: 'testing'

    receiver: 'notify-testing'
    group_by: [...]

  - match:
      env: "production"

    receiver: 'notify-productionA'
    group_wait: 1m

    continue: true

  - match_re:
      env: "produ.*"
      job: ".*"

    receiver: 'notify-productionB'
    group_wait: 30s
    group_interval: 5m
    repeat_interval: 1h
    group_by: ['job']


- match_re:
    owner: 'team-(B|C)'

  group_by: ['foo', 'bar']
  group_wait: 2m
  receiver: 'notify-BC'

- match:
    group_by: 'role'
  group_by: ['role']

  routes:
  - match:
      env: 'testing'
    receiver: 'notify-testing'
    routes:
    - match:
        wait: 'long'
      group_wait: 2m
`

	var ctree config.Route
	if err := yaml.UnmarshalStrict([]byte(in), &ctree); err != nil {
		t.Fatal(err)
	}
	var (
		def  = DefaultRouteOpts
		tree = NewRoute(&ctree, nil)
	)
	lset := func(labels ...string) map[model.LabelName]struct{} {
		s := map[model.LabelName]struct{}{}
		for _, ls := range labels {
			s[model.LabelName(ls)] = struct{}{}
		}
		return s
	}

	tests := []struct {
		input  model.LabelSet
		result []*RouteOpts
		keys   []string
	}{
		{
			input: model.LabelSet{
				"owner": "team-A",
			},
			result: []*RouteOpts{
				{
					Receiver:       "notify-A",
					GroupBy:        def.GroupBy,
					GroupByAll:     false,
					GroupWait:      def.GroupWait,
					GroupInterval:  def.GroupInterval,
					RepeatInterval: def.RepeatInterval,
				},
			},
			keys: []string{"{}/{owner=\"team-A\"}"},
		},
		{
			input: model.LabelSet{
				"owner": "team-A",
				"env":   "unset",
			},
			result: []*RouteOpts{
				{
					Receiver:       "notify-A",
					GroupBy:        def.GroupBy,
					GroupByAll:     false,
					GroupWait:      def.GroupWait,
					GroupInterval:  def.GroupInterval,
					RepeatInterval: def.RepeatInterval,
				},
			},
			keys: []string{"{}/{owner=\"team-A\"}"},
		},
		{
			input: model.LabelSet{
				"owner": "team-C",
			},
			result: []*RouteOpts{
				{
					Receiver:       "notify-BC",
					GroupBy:        lset("foo", "bar"),
					GroupByAll:     false,
					GroupWait:      2 * time.Minute,
					GroupInterval:  def.GroupInterval,
					RepeatInterval: def.RepeatInterval,
				},
			},
			keys: []string{"{}/{owner=~\"^(?:team-(B|C))$\"}"},
		},
		{
			input: model.LabelSet{
				"owner": "team-A",
				"env":   "testing",
			},
			result: []*RouteOpts{
				{
					Receiver:       "notify-testing",
					GroupBy:        lset(),
					GroupByAll:     true,
					GroupWait:      def.GroupWait,
					GroupInterval:  def.GroupInterval,
					RepeatInterval: def.RepeatInterval,
				},
			},
			keys: []string{"{}/{owner=\"team-A\"}/{env=\"testing\"}"},
		},
		{
			input: model.LabelSet{
				"owner": "team-A",
				"env":   "production",
			},
			result: []*RouteOpts{
				{
					Receiver:       "notify-productionA",
					GroupBy:        def.GroupBy,
					GroupByAll:     false,
					GroupWait:      1 * time.Minute,
					GroupInterval:  def.GroupInterval,
					RepeatInterval: def.RepeatInterval,
				},
				{
					Receiver:       "notify-productionB",
					GroupBy:        lset("job"),
					GroupByAll:     false,
					GroupWait:      30 * time.Second,
					GroupInterval:  5 * time.Minute,
					RepeatInterval: 1 * time.Hour,
				},
			},
			keys: []string{
				"{}/{owner=\"team-A\"}/{env=\"production\"}",
				"{}/{owner=\"team-A\"}/{env=~\"^(?:produ.*)$\",job=~\"^(?:.*)$\"}",
			},
		},
		{
			input: model.LabelSet{
				"group_by": "role",
			},
			result: []*RouteOpts{
				{
					Receiver:       "notify-def",
					GroupBy:        lset("role"),
					GroupByAll:     false,
					GroupWait:      def.GroupWait,
					GroupInterval:  def.GroupInterval,
					RepeatInterval: def.RepeatInterval,
				},
			},
			keys: []string{"{}/{group_by=\"role\"}"},
		},
		{
			input: model.LabelSet{
				"env":      "testing",
				"group_by": "role",
			},
			result: []*RouteOpts{
				{
					Receiver:       "notify-testing",
					GroupBy:        lset("role"),
					GroupByAll:     false,
					GroupWait:      def.GroupWait,
					GroupInterval:  def.GroupInterval,
					RepeatInterval: def.RepeatInterval,
				},
			},
			keys: []string{"{}/{group_by=\"role\"}/{env=\"testing\"}"},
		},
		{
			input: model.LabelSet{
				"env":      "testing",
				"group_by": "role",
				"wait":     "long",
			},
			result: []*RouteOpts{
				{
					Receiver:       "notify-testing",
					GroupBy:        lset("role"),
					GroupByAll:     false,
					GroupWait:      2 * time.Minute,
					GroupInterval:  def.GroupInterval,
					RepeatInterval: def.RepeatInterval,
				},
			},
			keys: []string{"{}/{group_by=\"role\"}/{env=\"testing\"}/{wait=\"long\"}"},
		},
	}

	for _, test := range tests {
		var matches []*RouteOpts
		var keys []string

		for _, r := range tree.Match(test.input) {
			matches = append(matches, &r.RouteOpts)
			keys = append(keys, r.Key())
		}

		if !reflect.DeepEqual(matches, test.result) {
			t.Errorf("\nexpected:\n%v\ngot:\n%v", test.result, matches)
		}

		if !reflect.DeepEqual(keys, test.keys) {
			t.Errorf("\nexpected:\n%v\ngot:\n%v", test.keys, keys)
		}
	}
}

func TestRouteWalk(t *testing.T) {
	in := `
receiver: 'notify-def'

routes:
- match:
    owner: 'team-A'

  receiver: 'notify-A'

  routes:
  - match:
      env: 'testing'

    receiver: 'notify-testing'
    group_by: [...]

  - match:
      env: "production"

    receiver: 'notify-productionA'
    group_wait: 1m

    continue: true

  - match_re:
      env: "produ.*"
      job: ".*"

    receiver: 'notify-productionB'
    group_wait: 30s
    group_interval: 5m
    repeat_interval: 1h
    group_by: ['job']


- match_re:
    owner: 'team-(B|C)'

  group_by: ['foo', 'bar']
  group_wait: 2m
  receiver: 'notify-BC'

- match:
    group_by: 'role'
  group_by: ['role']

  routes:
  - match:
      env: 'testing'
    receiver: 'notify-testing'
    routes:
    - match:
        wait: 'long'
      group_wait: 2m
`

	var ctree config.Route
	if err := yaml.UnmarshalStrict([]byte(in), &ctree); err != nil {
		t.Fatal(err)
	}
	tree := NewRoute(&ctree, nil)

	expected := []string{
		"notify-def",
		"notify-A",
		"notify-testing",
		"notify-productionA",
		"notify-productionB",
		"notify-BC",
		"notify-def",
		"notify-testing",
		"notify-testing",
	}

	var got []string
	tree.Walk(func(r *Route) {
		got = append(got, r.RouteOpts.Receiver)
	})

	if !reflect.DeepEqual(got, expected) {
		t.Errorf("\nexpected:\n%v\ngot:\n%v", expected, got)
	}
}

func TestInheritParentGroupByAll(t *testing.T) {
	in := `
routes:
- match:
    env: 'parent'
  group_by: ['...']

  routes:
  - match:
      env: 'child1'

  - match:
      env: 'child2'
    group_by: ['foo']
`

	var ctree config.Route
	if err := yaml.UnmarshalStrict([]byte(in), &ctree); err != nil {
		t.Fatal(err)
	}

	tree := NewRoute(&ctree, nil)
	parent := tree.Routes[0]
	child1 := parent.Routes[0]
	child2 := parent.Routes[1]
	require.Equal(t, parent.RouteOpts.GroupByAll, true)
	require.Equal(t, child1.RouteOpts.GroupByAll, true)
	require.Equal(t, child2.RouteOpts.GroupByAll, false)
}
