;; SPDX-License-Identifier: AGPL-3.0-or-later
;; SPDX-FileCopyrightText: 2025 Jonathan D.A. Jewell
;; ECOSYSTEM.scm — project-wharf

(ecosystem
  (version "1.0.0")
  (name "project-wharf")
  (type "project")
  (purpose "*Wharf* is a revolutionary approach to Content Management System (CMS) security that separates administration from runtime. Instead of plugins with full system access running on your live site, Wharf ...")

  (position-in-ecosystem
    "Part of hyperpolymath ecosystem. Follows RSR guidelines.")

  (related-projects
    (project (name "rhodium-standard-repositories")
             (url "https://github.com/hyperpolymath/rhodium-standard-repositories")
             (relationship "standard")))

  (what-this-is "*Wharf* is a revolutionary approach to Content Management System (CMS) security that separates administration from runtime. Instead of plugins with full system access running on your live site, Wharf ...")
  (what-this-is-not "- NOT exempt from RSR compliance"))
