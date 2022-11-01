# monoplatform_nrf9160-ltem1rc

## Getting start

### About
このソフトウェアはさくらのモノプラットフォーム向けのサンプルプログラムです。
同梱しているPCBファイルで製造した基板上で動作します。(SCO-LTEM1RC-A)


### Install nRF Connect SDK

See [nRF Connect SDK Getting started](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrf/getting_started.html).  
If you want to install the development environment quickly, see [Installing the nRF Connect SDK through nRF Connect for Desktop](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrf/gs_assistant.html#gs-assistant).

Using nRF Connect SDK v1.7.1 .

### Clone this repository

```
git clone https://github.com/sakura-internet/sipf-std-client_nrf9160.git
cd sipf-std-client_nrf9160
```

### Clean

```
rm -rf build
```

### Build

Use `build.sh` for build.

```
./build.sh [target] [board]
```

target

- develop (default)
- staging
- production
- local

board

- scm-ltem1nrf_nrf9160ns (default)
- nrf9160dk_nrf9160_ns
- thingy91_nrf9160_ns

For develop / SCM-LTEM1NRF
```
./build.sh
```

For production / SCM-LTEM1NRF
```
./build.sh production
```

For production / nRF9160DK
```
./build.sh production nrf9160dk_nrf9160_ns
```

For local only
```
cp -n prj.conf.develop prj.conf.local
vi prj.conf.local
./build.sh local
```

### Flash

`nrfjprog` is required.

For develop
```
./flash.sh
```

For production
```
./flash.sh production
```

OR

Write the HEX image file 'build/{ENV}/zephyr/merged.hex' using nRF Connect `Programmer' application.

---
Please refer to the [Wiki(Japanese)](https://github.com/sakura-internet/sipf-std-client_nrf9160/wiki) for specifications.
