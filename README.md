# Apple Home Key Reader

<p float="left">
  <img src="./assets/HOME.KEY.PN532.PHONE.DEMO.webp" alt="![Home Key on an iPhone with PN532]" width=250px>
  <img src="./assets/HOME.KEY.PN532.WATCH.DEMO.webp" alt="![Home Key on an Apple Watch with PN532]" width=250px>
  <img src="./assets/HOME.KEY.ACR122U.PHONE.webp" alt="![Home Key on an Apple Watch with ACR122U]" width=250px>
</p>

# Overview

This project offers a demonstration of an Apple Home Key Reader built in Python. It includes:
* Fully functional Apple Home Key NFC authentication;
* NFC Express mode support;
* HAP configuration (as a virtual lock);

It's intended for makers and developers interested in building practical and user-friendly applications using this example.  
Feel free to give it a try! :)

# Requirements

Running this project requires the following:
* An operating system: Linux or macOS;
* Python installation version 3.9 or higher (earlier versions might work but haven't been tested);
* A PN532 module connected to a PC or SBC via UART (not through I2C or SPI);
* Either Ethernet or Wi-Fi to ensure HAP can be discovered.

When using a PC, connect the PN532 to a UART adapter, and then connect the adapter to the PC as follows:
<p float="left">
  <img src="./assets/PN532.CONNECTION.DEMO.webp" alt="![Connecting PN532]" width=500px>
</p>


# Installation & running

Code has been tested using Python `3.9`, `3.10`, `3.11` on `macOS` and `Linux`. Windows support status is unknown.  
Other OS + Python version combos were not verified but may still work.


1. (Optionally). Create and activate a venv:
    ```
    python3 -m venv ./venv

    source ./venv/bin/activate
    ```
2. Install dependencies:
    ```
    python3 -m pip install -r requirements.txt
    ```
3. Configure the application via the text editor of choice:
    ```
    nano configuration.json 
    ```
    3.1. Find NFC device port:    

        # linux
        ls /dev/*

        # macOS
        ls /dev/tty.*
    3.2. Copy the port without the `tty.` part, insert it into `port` field;  
    3.3. If you don't use a PN532, set `broadcast` to false and `driver` to appropriate value, otherwise leave as is.
3. Run application:
    ```
    python3 main.py
    ```

# Configuration

Configuration is done via a JSON file `configuration.json`, with the following 4 blocks configurable:

* `logging`:
    * level: level to log messages at. All logs related to this codebase use INFO level (20).
* `nfc`: configuration of the NFC frontend used:
    * `port`: path to serial port of the connected NFC module;
    * `driver`: nfcpy driver to use with your device. Implementation was only tested for PN532, other modules have to be verified separately (if supported by nfcpy);
    * `broadcast`: configures if to use broadcast frames and ECP. If this parameter is true but used NFC device is not based on PN532, will cause an exception to be raised, set to false only if such problems occur;
* `hap`: configuration of the HAP-python library, better left unchanged;
    * `port`: network port of the virtual accessory;
    * `persist`: file to store HAP-python pairing data in.
* `homekey`:
    * `persist`: file to save endpoint and issuer configuration data in;
    * `express`: configures if to trigger express mode on devices that have it enabled. If set to `false`, bringing a device to the reader will display the key on the screen while asking for biometric authentication. Beware that this doesn't increase security as express mode is disabled on ECP level, so a would-be attacker could always 'excite' the device with express ECP frame and bring it to the reader;
    * `finish`: color of the home key art to display on your device. 
       Usually, finish of the first NFC lock added to your home defines which color the keys are going to be, even if more locks are added;  
       Possible values: `black` `tan` `gold` `silver`;
    * `flow`: minimum viable digital key transaction flow do. By default, reader attempts to do as least actions as possible, with fallback to next level of authentication only happening if the previous one failed. Setting this setting to `standard` or `attestation` will force protocol to fall back to those flows even if they're not required for successful auth.  
    Possible values: `fast` `standard` `attestation`.


# Project structure

Project is split into following primary modules:
- `main.py` - initialize and start all primary classes, configure device ports, etc;
- `accessory.py` - service definitions for HAP, contains no logic, with it forwarded to `service.py`;
- `service.py` - implements core application functionality, parsing HAP messages and generating responses to them, initiating NFC communication.
- `homekey.py` - homekey NFC part of the protocol implementation;  

Other modules:
- `repository.py` - implements homekey configuration state storage;
- `bfclf.py` - implementation of Broadcast frames for pn532;
- `entity.py` - entity definitions;
- `util/*` - protocol implementations, data structures, cryptography, other utility methods.

Two files will be created as the result of you running the application, assuming no settings were changed:
- `hap.state`: contains pairing data needed for HAP-python;
- `homekey.json`: contains all lock configuration data formatted in a human-readable form.


# Terminology

- EC: elliptic curve;
- HAP: Homekit Accessory Protocol, aka Network/Bluetooth part;
- Issuer: a party that enrolls endpoints. Each issuer is a person with an iCloud account;
- Endpoint: a device that's enrolled/paired to the lock;
- Enrollment: payload that contains data that was used to enroll the Endpoint to the device.  
  Can be either `hap`, meaning that the Endpoint was added via HAP, or `attestation`, meaning that endpoint was enrolled via NFC attestation flow.


# Contributing

The project is quite far from ideal since most of the codebase remains unchanged from my original local project, which was primarily utilized during the reverse-engineering phase. 

As a result, there are numerous opportunities for enhancement:

* Fixing potential typos in README and code;
* Adding tests to insure stability if a refactor is made;
* Re-writing pieces of service/homekey code to reduce code size, improve readability;
* Improve logging for better protocol analysis;
* **HAP command implementations**:
  * `remove_device_credential`;
  * `get_nfc_access_control_point` - no idea what it should do;
  * Re-test and verify validity of other methods;
* Re-write NFC stack to improve device support.

In case you're planning on tackling one of those, feel free to raise an issue to discuss potential solution and approach.

Codebase is formatted with default `black` and `isort` configurations, linted with `pylint`.  
Before making a contribution, verify that they were used for best code diffs and quality;


# Notes

- This code is provided as-is. Considering the sensitive nature of authentication and security, I assume no responsibility for any issues that may arise while using this project;  
- Information is provided here for learning and DIY purposes only, usage in commercial applications is highly discouraged.
- Refrain from posting raw logs as they may contain sensitive information, such as reader private key, issuer id's, etc.
- If you find a bug, feel free to raise an issue;

# Credits

This project would have been impossible without the contributions of:
* [@kupa22](https://github.com/kupa22) - for full HAP part analysis, NFC protocol research;
* [@kormax](https://github.com/kormax) - ECP, NFC protocol research;  

Special thanks to:
* [@gm3197](https://github.com/gm3197) - for finding clues about ISO18013 being used in Home Key protocol;
* [@KhaosT](https://github.com/KhaosT/HAP-NodeJS/commit/80cdb1535f5bee874cc06657ef283ee91f258815) - for creating a demo that caused Home Key to appear in Wallet, which partially inspired me/others to go on this journey;
* @ikalchev and @bdraco for developing HAP-Python and helping with accepting in changes that were needed for this project;
* Other people, who gave their input on demo app improvement.

# References

* Learning material:
    - [Apple Home Key - kupa22](https://github.com/kupa22/apple-homekey) - HAP part, deriviation info;
    - [Apple Home Key - kormax](https://github.com/kormax/apple-home-key) - extra Home Key info;
    - [Enhanced Contactless Polling](https://github.com/kormax/apple-enhanced-contactless-polling) - Broadcast Frames, ECP.
