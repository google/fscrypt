/*
 * policy_test.go - tests for creating and modifying policies
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

import "testing"

// Makes a protector and policy
func makeBoth() (*Protector, *Policy, error) {
	protector, err := CreateProtector(testContext, testProtectorName, goodCallback)
	if err != nil {
		return nil, nil, err
	}
	policy, err := CreatePolicy(testContext, protector)
	if err != nil {
		cleanupProtector(protector)
		return nil, nil, err
	}
	return protector, policy, nil
}

func cleanupProtector(protector *Protector) {
	protector.Lock()
	protector.Destroy()
}

func cleanupPolicy(policy *Policy) {
	policy.Lock()
	policy.Destroy()
}

// Tests that we can make a policy/protector pair
func TestCreatePolicy(t *testing.T) {
	pro, pol, err := makeBoth()
	if err != nil {
		t.Error(err)
	}
	cleanupPolicy(pol)
	cleanupProtector(pro)
}

// Tests that we can add another protector to the policy
func TestPolicyGoodAddProtector(t *testing.T) {
	pro1, pol, err := makeBoth()
	defer cleanupProtector(pro1)
	defer cleanupPolicy(pol)
	if err != nil {
		t.Fatal(err)
	}

	pro2, err := CreateProtector(testContext, testProtectorName2, goodCallback)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupProtector(pro2)

	err = pol.AddProtector(pro2)
	if err != nil {
		t.Error(err)
	}
}

// Tests that we cannot add a protector to a policy twice
func TestPolicyBadAddProtector(t *testing.T) {
	pro, pol, err := makeBoth()
	defer cleanupProtector(pro)
	defer cleanupPolicy(pol)
	if err != nil {
		t.Fatal(err)
	}

	if pol.AddProtector(pro) == nil {
		t.Error("we should not be able to add the same protector twice")
	}
}

// Tests that we can remove a protector we added
func TestPolicyGoodRemoveProtector(t *testing.T) {
	pro1, pol, err := makeBoth()
	defer cleanupProtector(pro1)
	defer cleanupPolicy(pol)
	if err != nil {
		t.Fatal(err)
	}

	pro2, err := CreateProtector(testContext, testProtectorName2, goodCallback)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupProtector(pro2)

	err = pol.AddProtector(pro2)
	if err != nil {
		t.Fatal(err)
	}

	err = pol.RemoveProtector(pro1)
	if err != nil {
		t.Error(err)
	}
}

// Tests various bad ways to remove protectors
func TestPolicyBadRemoveProtector(t *testing.T) {
	pro1, pol, err := makeBoth()
	defer cleanupProtector(pro1)
	defer cleanupPolicy(pol)
	if err != nil {
		t.Fatal(err)
	}

	pro2, err := CreateProtector(testContext, testProtectorName2, goodCallback)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupProtector(pro2)

	if pol.RemoveProtector(pro2) == nil {
		t.Error("we should not be able to remove a protector we did not add")
	}

	if pol.RemoveProtector(pro1) == nil {
		t.Error("we should not be able to remove all the protectors from a policy")
	}
}
