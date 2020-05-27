# Mbed-E2C

## Prerequisites
1. The GNU ARM embedded toolchain (https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads).
2. GDB-with python pulgin (for debugging script only)
3. mbed-cli (https://github.com/ARMmbed/mbed-cli)

## To compile the code.
1. mbed new .
or 
1. mbed deploy .
2. mbed compile -t GCC_ARM -m NUCLEO_F401RE

To flash use -f at the end.

## To measure energy:
Define in code : digitalout dout(<pin number>)
Attach the trigger pin of the logic pro to the pin.
Change pin from 0 to 1 at start of code snippet that needs to be measured
 and back to 0 at the end.

Logic 8 pro software is available at https://www.saleae.com/downloads/

  
