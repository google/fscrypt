/*
 * hashing_test.go - tests for computing and benchmarking hashing costs
 *
 * Copyright 2017 Google Inc.
 * Author: Joe Richey (joerichey@google.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package actions

import (
	"io/ioutil"
	"log"
	"testing"
	"time"
)

// Tests that we can find valid hashing costs for various time targets and the
// estimations are somewhat close to the targets.
func TestCostsSearch(t *testing.T) {
	for _, target := range []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		500 * time.Millisecond,
	} {
		costs, err := getHashingCosts(target)
		if err != nil {
			t.Error(err)
		}
		actual, err := timeHashingCosts(costs)
		if err != nil {
			t.Error(err)
		}

		if actual*3 < target {
			t.Errorf("actual=%v is too small (target=%v)", actual, target)
		}
		if target*3 < actual {
			t.Errorf("actual=%v is too big (target=%v)", actual, target)
		}
	}
}

func benchmarkCostsSearch(b *testing.B, target time.Duration) {
	// Disable logging for benchmarks
	log.SetOutput(ioutil.Discard)
	for i := 0; i < b.N; i++ {
		_, err := getHashingCosts(target)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCostsSearch10ms(b *testing.B) {
	benchmarkCostsSearch(b, 10*time.Millisecond)
}

func BenchmarkCostsSearch100ms(b *testing.B) {
	benchmarkCostsSearch(b, 100*time.Millisecond)
}

func BenchmarkCostsSearch1s(b *testing.B) {
	benchmarkCostsSearch(b, time.Second)
}
