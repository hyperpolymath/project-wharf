;; SPDX-License-Identifier: PMPL-1.0-or-later
(bot-directive
  (bot "echidnabot")
  (scope "formal verification and fuzzing")
  (allow ("analysis" "fuzzing" "proof checks"))
  (deny ("write to crypto module" "write to mooring protocol"))
  (notes "May open findings; code changes to crypto.rs or mooring.rs require explicit approval"))
