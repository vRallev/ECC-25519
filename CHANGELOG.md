## 1.0.2 (2016-05-19)

- Includes net.i2p.crypto.eddsa artifact in java module

## 1.0.1 (2015-07-05)

Bugfixes:

  - Potential signing bug described by doctorevil
  - Remove slow Java implementation because it isn't recommended anymore
  - Fix not side-effect free constructor
  - Fix not clamped private key in sign method