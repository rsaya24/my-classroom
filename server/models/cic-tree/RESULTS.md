# Detector upgrade: measured results

| Split | Model | Accuracy | Precision | Recall | F1 | False-positive rate |
|---|---|---:|---:|---:|---:|---:|
| validation | tree | 0.965 | 0.977 | 0.976 | 0.977 | 0.066 |
| validation | linear_same_training_rows | 0.882 | 0.883 | 0.967 | 0.924 | 0.362 |
| same_distribution_test | tree | 0.972 | 0.982 | 0.980 | 0.981 | 0.052 |
| same_distribution_test | linear_same_training_rows | 0.893 | 0.893 | 0.972 | 0.931 | 0.332 |
| friday_test | tree | 0.606 | 0.833 | 0.321 | 0.464 | 0.073 |
| friday_test | linear_same_training_rows | 0.442 | 0.458 | 0.283 | 0.350 | 0.378 |

## Boundaries

- Friday was examined in earlier work: this is a development comparison, not a pristine external validation.
- Balanced class weights and label sampling change score interpretation; scores are not calibrated.
- Do not tune further on Friday and present it as a fresh test.
- TrafficLabelling overlaps the same benchmark and is not an external test.
- Exact tree paths explain model decisions, not attacker intent or causal mechanisms.

