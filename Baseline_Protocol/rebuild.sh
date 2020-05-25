rm -rf BUILD/NUCLEO_F401RE/GCC_ARM/mbed-os-example-wifi*
rm -rf BUILD/NUCLEO_F401RE/GCC_ARM/main*
rm -rf BUILD/NUCLEO_F401RE/GCC_ARM/mbed_config.h

mbed compile -t GCC_ARM -m NUCLEO_F401RE
