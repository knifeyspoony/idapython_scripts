# Contents
Some simple IDA Pro scripts.

## [ks_call_highlighter](ks_call_highlighter.py)
A very basic script that highlights call instructions.

## [ks_winstatus](ks_winstatus.py)
Automatically sets immediate constants above 0xC0000000 to their equivalent Windows error code, if applicable. Could (should) probably be improved to avoid false positives.

## [bit_tester](bit_tester)
Somewhat useful. It lets you apply enumeration values from bit tests. Includes a guide for writing a basic GUI plugin for IDA Pro using python and Qt5.

In cases where this test:
```assembly
and eax, 4h      
test eax, eax     
jnz SOMEWHERE
```

is compiled like this:
```assembly
bt al, 2h
jnz SOMEWHERE        
```

bit_tester will search for enumeration values of 0x4, and allow you to assign them in place of of 0x2.

