# Attack on NIST candidate signature EagleSign

This repository contains example code to demonstrate the attack on
EagleSign described in [this official comment][commenturl] on the
pqc-forum mailing list.

The attack is mounted against the unmodified reference implementation of
EagleSign. With 100,000 signature samples, for instance, it recovers
around 1020 coefficients out of 1024 of the secret key element G for 
parameter set EagleSign-3, and 972 out of 1024 for parameter set
EagleSign-5.

To build and run the attack:
```
cd eaglesign_ref
make
./test/test_attack_eaglesign3          #for parameter set EagleSign-3
./test/test_attack_eaglesign5 250000   #for parameter set EagleSign-5 with 250,000 signature samples
```

## Remarks

* The compilation options are modified from the reference implementation:
  we add `-Ofast -march=native` for a faster attack. Needless to say,
  everything works just as well without this change (just slower). Feel
  free to edit back the Makefile as appropriate.

* The attack, although quite effective already, is highly unoptimized
  (e.g., it throws away around 97% of all signatures for parameter set
  EagleSign-3, and even more for parameter set EagleSign-5). A more
  efficient version will be provided later.

* For parameter set EagleSign-5, G is actually a 2×2 matrix, and this
  code recovers the top left entry for simplicity. The other entries can
  be recovered in exactly the same way by adjusting which entry of Z and
  C we average out.

—Mehdi Tibouchi, July 19, 2023.

[commenturl]: https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/zas5PLiBe6A/m/A2KSHtqUAgAJ
