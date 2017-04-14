****
NEWS
****

HEAD
====

Fixes
-----

- Fixed handling of k8s NetworkPolicy matchLabels
- Fixed behaviour to allow all sources if the k8s NetworkPolicy has empty From

Features
--------

- Support for Kubernetes NetworkPolicy L4 rules
- AllowRules now support matching against list of labels
- Added new CoverAll flag to mark policy nodes which should always have coverage
- Improved logging readability (`GH #499 <https://github.com/cilium/cilium/pull/499>`_)
- Reduced size of cilium binary from 27M to 17M
- Decreased endpoint operations time by introducing parallelization in regeneration
- Replaced all endpoint synchronous CLI operations with asynchronous CLI operations

0.8.0
=====

- First initial release
