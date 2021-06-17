# Contents
Some simple IDA Pro scripts.

## ks_call_highlighter
A very basic script that highlights call instructions.

## ks_winstatus
Automatically sets immediate constants above 0xC0000000 to their equivalent Windows error code, if applicable. Could (should) probably be improved to avoid false positives.

## bit_tester
Somewhat useful. It lets you apply enumeration values from bit tests.

In cases where this test:
```assembly
and eax, 4h      
test eax, eax     
jnz SOMEWHERE
```

Is compiled like this:
```assembly
bt al, 2h
jnz SOMEWHERE        
```

In this case, bit_tester will search for enumeration values of 0x4, and allow you to assign them in place of of 0x2.

