Simple module to jame a given frequency for a specified amount of seconds. This
code was ported from [AndrewMohowk](https://github.com/AndrewMohawk/RfCatHelpers/blob/master/RFJammer.py).
Note: Jamming tends to violate FCC rules and most likely other rules in your area.

## Options ##

  **FREQ**

  Frequency to brute force.  Default: 433880000

  **BAUD**

  Baud rate: Default: 4800

  **POWER**

  Power level to specify.  Default: 100

  **SECONDS**

  How many seconds to jam the signal. Default: 15

  **INDEX**

  USB Index number.  Default 0

## Scenarios

  Jam a given signal for 15 seconds

```
hwbridge > run post/hardware/rftransceiver/jammer 

[*] Jamming 433880000 for 15 seconds...
[*] Finished jamming
```
