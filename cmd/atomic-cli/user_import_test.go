/*
 * This file is part of the Passport Atomic Stack (https://github.com/libatomic/atomic).
 * Copyright (c) 2026 Passport, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/libatomic/atomic/pkg/util"
)

func flagSet(names ...string) func(string) bool {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return func(name string) bool {
		_, ok := set[name]
		return ok
	}
}

// poisonedEnrollInput is what BindFlagsFromContext produces for a vanilla
// --mode unsubscribe: enroll flags with non-zero CLI defaults (especially
// default_plan_behavior=all) plus fields Validate does not reject.
func poisonedEnrollInput(mode atomic.UserImportMode, planID atomic.ID) *atomic.UserImportInput {
	all := atomic.UserImportDefaultPlanBehaviorAll
	subAll := atomic.UserImportSubscribeBehaviorAllUsers
	trialAll := atomic.UserImportTrialBehaviorAll
	retain := atomic.UserImportExistingUserBehaviorRetain
	existing := atomic.UserImportAccountBehaviorExisting
	aggregate := atomic.UserImportDiscountBehaviorAggregate
	return &atomic.UserImportInput{
		Mode:                  ptr.Pointer(mode),
		DefaultPlanBehavior:   &all,
		SubscribeBehavior:     &subAll,
		TrialBehavior:         &trialAll,
		TrialExistingUsers:    ptr.True,
		ExistingUserBehavior:  &retain,
		SubscribePlans:        util.Slice[atomic.ID]{planID},
		StripeAccountBehavior: &existing,
		DiscountBehavior:      &aggregate,
		RebuildAudiences:      ptr.True,
	}
}

func TestClearUnsubscribeEnrollDefaults(t *testing.T) {
	planID := atomic.NewID()
	all := atomic.UserImportDefaultPlanBehaviorAll
	nonePlan := atomic.UserImportDefaultPlanBehaviorNone
	noneSub := atomic.UserImportSubscribeBehaviorNone

	t.Run("unset clears enroll fields to none/nil", func(t *testing.T) {
		in := poisonedEnrollInput(atomic.UserImportModeUnsubscribe, planID)
		clearUnsubscribeEnrollDefaults(in, flagSet())

		if in.DefaultPlanBehavior == nil || *in.DefaultPlanBehavior != nonePlan {
			t.Fatalf("default_plan_behavior: got %v want none", in.DefaultPlanBehavior)
		}
		if in.SubscribeBehavior == nil || *in.SubscribeBehavior != noneSub {
			t.Fatalf("subscribe_behavior: got %v want none", in.SubscribeBehavior)
		}
		if in.TrialBehavior != nil {
			t.Fatalf("trial_behavior: got %v want nil", in.TrialBehavior)
		}
		if in.TrialExistingUsers != nil {
			t.Fatalf("trial_existing_users: got %v want nil", in.TrialExistingUsers)
		}
		if in.ExistingUserBehavior != nil {
			t.Fatalf("existing_user_behavior: got %v want nil", in.ExistingUserBehavior)
		}
		if len(in.SubscribePlans) != 0 {
			t.Fatalf("subscribe_plans: got %v want nil", in.SubscribePlans)
		}
	})

	t.Run("explicit default_plan_behavior is left alone", func(t *testing.T) {
		in := poisonedEnrollInput(atomic.UserImportModeUnsubscribe, planID)
		clearUnsubscribeEnrollDefaults(in, flagSet("default_plan_behavior"))
		if in.DefaultPlanBehavior == nil || *in.DefaultPlanBehavior != all {
			t.Fatalf("default_plan_behavior: got %v want all", in.DefaultPlanBehavior)
		}
		if in.SubscribeBehavior == nil || *in.SubscribeBehavior != noneSub {
			t.Fatalf("subscribe_behavior should still clear, got %v", in.SubscribeBehavior)
		}
	})

	for _, flag := range []string{
		"subscribe_behavior",
		"trial_behavior",
		"trial_existing_users",
		"existing_user_behavior",
		"subscribe_plans",
	} {
		t.Run("explicit "+flag+" is left alone", func(t *testing.T) {
			in := poisonedEnrollInput(atomic.UserImportModeUnsubscribe, planID)
			before := *in
			clearUnsubscribeEnrollDefaults(in, flagSet(flag))
			switch flag {
			case "subscribe_behavior":
				if in.SubscribeBehavior == nil || *in.SubscribeBehavior != *before.SubscribeBehavior {
					t.Fatalf("subscribe_behavior: got %v want %v", in.SubscribeBehavior, before.SubscribeBehavior)
				}
			case "trial_behavior":
				if in.TrialBehavior == nil || *in.TrialBehavior != *before.TrialBehavior {
					t.Fatalf("trial_behavior: got %v want %v", in.TrialBehavior, before.TrialBehavior)
				}
			case "trial_existing_users":
				if in.TrialExistingUsers == nil || *in.TrialExistingUsers != *before.TrialExistingUsers {
					t.Fatalf("trial_existing_users: got %v want %v", in.TrialExistingUsers, before.TrialExistingUsers)
				}
			case "existing_user_behavior":
				if in.ExistingUserBehavior == nil || *in.ExistingUserBehavior != *before.ExistingUserBehavior {
					t.Fatalf("existing_user_behavior: got %v want %v", in.ExistingUserBehavior, before.ExistingUserBehavior)
				}
			case "subscribe_plans":
				if len(in.SubscribePlans) != 1 || in.SubscribePlans[0] != planID {
					t.Fatalf("subscribe_plans: got %v want [%s]", in.SubscribePlans, planID)
				}
			}
			if in.DefaultPlanBehavior == nil || *in.DefaultPlanBehavior != nonePlan {
				t.Fatalf("unset default_plan_behavior should still clear, got %v", in.DefaultPlanBehavior)
			}
		})
	}

	t.Run("all explicit flags leave enroll fields", func(t *testing.T) {
		in := poisonedEnrollInput(atomic.UserImportModeUnsubscribe, planID)
		clearUnsubscribeEnrollDefaults(in, flagSet(
			"default_plan_behavior",
			"subscribe_behavior",
			"trial_behavior",
			"trial_existing_users",
			"existing_user_behavior",
			"subscribe_plans",
		))
		if in.DefaultPlanBehavior == nil || *in.DefaultPlanBehavior != all {
			t.Fatalf("default_plan_behavior: got %v want all", in.DefaultPlanBehavior)
		}
		if in.SubscribeBehavior == nil || *in.SubscribeBehavior != atomic.UserImportSubscribeBehaviorAllUsers {
			t.Fatalf("subscribe_behavior: got %v", in.SubscribeBehavior)
		}
		if in.TrialBehavior == nil || *in.TrialBehavior != atomic.UserImportTrialBehaviorAll {
			t.Fatalf("trial_behavior: got %v", in.TrialBehavior)
		}
		if in.TrialExistingUsers == nil || !*in.TrialExistingUsers {
			t.Fatalf("trial_existing_users: got %v", in.TrialExistingUsers)
		}
		if in.ExistingUserBehavior == nil || *in.ExistingUserBehavior != atomic.UserImportExistingUserBehaviorRetain {
			t.Fatalf("existing_user_behavior: got %v", in.ExistingUserBehavior)
		}
		if len(in.SubscribePlans) != 1 || in.SubscribePlans[0] != planID {
			t.Fatalf("subscribe_plans: got %v", in.SubscribePlans)
		}
	})

	for _, mode := range []atomic.UserImportMode{
		atomic.UserImportModeImport,
		atomic.UserImportModeUpdate,
	} {
		t.Run("non-unsubscribe "+string(mode)+" is a no-op", func(t *testing.T) {
			in := poisonedEnrollInput(mode, planID)
			clearUnsubscribeEnrollDefaults(in, flagSet())
			if in.DefaultPlanBehavior == nil || *in.DefaultPlanBehavior != all {
				t.Fatalf("default_plan_behavior should stay all, got %v", in.DefaultPlanBehavior)
			}
			if in.SubscribeBehavior == nil || *in.SubscribeBehavior != atomic.UserImportSubscribeBehaviorAllUsers {
				t.Fatalf("subscribe_behavior should stay, got %v", in.SubscribeBehavior)
			}
			if in.TrialBehavior == nil {
				t.Fatal("trial_behavior should stay")
			}
			if in.TrialExistingUsers == nil {
				t.Fatal("trial_existing_users should stay")
			}
			if in.ExistingUserBehavior == nil {
				t.Fatal("existing_user_behavior should stay")
			}
			if len(in.SubscribePlans) != 1 {
				t.Fatalf("subscribe_plans should stay, got %v", in.SubscribePlans)
			}
		})
	}

	t.Run("nil mode is a no-op", func(t *testing.T) {
		in := poisonedEnrollInput(atomic.UserImportModeUnsubscribe, planID)
		in.Mode = nil
		clearUnsubscribeEnrollDefaults(in, flagSet())
		if in.DefaultPlanBehavior == nil || *in.DefaultPlanBehavior != all {
			t.Fatalf("default_plan_behavior should stay all, got %v", in.DefaultPlanBehavior)
		}
	})

	t.Run("does not clear stripe_account_behavior discount_behavior rebuild_audiences", func(t *testing.T) {
		in := poisonedEnrollInput(atomic.UserImportModeUnsubscribe, planID)
		clearUnsubscribeEnrollDefaults(in, flagSet())
		if in.StripeAccountBehavior == nil || *in.StripeAccountBehavior != atomic.UserImportAccountBehaviorExisting {
			t.Fatalf("stripe_account_behavior: got %v want existing", in.StripeAccountBehavior)
		}
		if in.DiscountBehavior == nil || *in.DiscountBehavior != atomic.UserImportDiscountBehaviorAggregate {
			t.Fatalf("discount_behavior: got %v want aggregate", in.DiscountBehavior)
		}
		if in.RebuildAudiences == nil || !*in.RebuildAudiences {
			t.Fatalf("rebuild_audiences: got %v want true", in.RebuildAudiences)
		}
	})
}

func validUnsubscribeInput(in *atomic.UserImportInput, planID atomic.ID) {
	in.InstanceID = atomic.NewID()
	in.Filename = "users.csv"
	in.MimeType = "text/csv"
	in.Size = 1
	in.File = bytes.NewReader([]byte("login\nalice@example.com\n"))
	in.UnsubscribePlans = util.Slice[atomic.ID]{planID}
}

func TestClearUnsubscribeEnrollDefaultsValidate(t *testing.T) {
	planID := atomic.NewID()

	t.Run("cleared CLI defaults pass Validate", func(t *testing.T) {
		in := poisonedEnrollInput(atomic.UserImportModeUnsubscribe, planID)
		validUnsubscribeInput(in, planID)
		if err := in.Validate(); err == nil || !strings.Contains(err.Error(), "default_plan_behavior") {
			t.Fatalf("poisoned defaults should fail Validate, got %v", err)
		}
		clearUnsubscribeEnrollDefaults(in, flagSet())
		if err := in.Validate(); err != nil {
			t.Fatalf("cleared defaults should pass Validate, got %v", err)
		}
	})

	t.Run("explicit default_plan_behavior=all still fails Validate", func(t *testing.T) {
		in := poisonedEnrollInput(atomic.UserImportModeUnsubscribe, planID)
		validUnsubscribeInput(in, planID)
		clearUnsubscribeEnrollDefaults(in, flagSet("default_plan_behavior"))
		err := in.Validate()
		if err == nil || !strings.Contains(err.Error(), "default_plan_behavior") {
			t.Fatalf("expected default_plan_behavior error, got %v", err)
		}
	})
}
