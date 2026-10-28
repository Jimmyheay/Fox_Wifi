# ESP32 WiFi Hash Monster

<p align="center">
    <a href="https://github.com/G4lile0/ESP32-WiFi-Hash-Monster/blob/master/README.md"><img alt="Software License" src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>
    <a href="https://github.com/G4lile0/ESP32-WiFi-Hash-Monster/graphs/contributors"><img alt="Contributors" src="https://img.shields.io/github/contributors/G4lile0/ESP32-WiFi-Hash-Monster"/></a>
    <a href="https://twitter.com/intent/follow?screen_name=g4lile0"><img src="https://img.shields.io/twitter/follow/g4lile0?style=social&logo=twitter" alt="follow on Twitter"></a>
</p>

WiFi Fox passively records 802.11 packets to an SD card on M5Stack / ESP32 hardware.

90% of the code is based on the great [PacketMonitor32](https://github.com/spacehuhn/PacketMonitor32/) from   &nbsp; <a href="https://twitter.com/intent/follow?screen_name=spacehuhn"><img src="https://img.shields.io/twitter/follow/spacehuhn?style=social&logo=twitter" alt="follow on Twitter"></a> and the port to [M5Stack](https://m5stack.com/) from [macsbug](https://macsbug.wordpress.com/2018/01/11/packetmonitor32-with-m5stack/). It was a challenge to see if I could mimic the operation of [pwnagotchi](https://github.com/evilsocket/pwnagotchi)
<a href="https://twitter.com/intent/follow?screen_name=pwnagotchi"><img src="https://img.shields.io/twitter/follow/pwnagotchi?style=social&logo=twitter" alt="follow on Twitter"></a> in an ESP32 SoC.

![WiFi Fox sprite sheet](./assets/fox/fox-sheet.png)

When a wifi device connect to an AP with WPA2/PSK instead of sharing the wifi key they exchange 4 EAPOL messages, this method is known as the 4-way handshake, capturing these 4 packets is possible to guess the password using dictonary attacks or brute force attack, recentely there is a more efficent way to calculate the wifi key using just one PMKID packet.

Purple Hash Monster capture all the EAPOL / PMKID packets on the SD Card for further analysis.

Short press on first button will change enable incognito mode (Display and leds off) long press will enable the SD Card and all EAPOL / PMKID will be stored on the SD-Card.

Short press on the second button will change the display backlight brighness, long press will change the LED bars brightness.

Short press on the third button will change WiFi Channel, long press will enable **Auto-Channel** or **Smart-Channel** modes. 

**Auto-Channel**  hop between channels 1,6 and after 15 seconds. 

**Smart-Channel**  cover all the channels sequentially, but only hop if there is not new SSID, EAPOL or DEAUTHS after 15 seconds. 

The display uses the compact fox atlas above. Sixteen 64×64 poses are packed at
4 bits per pixel in firmware flash and streamed at 2× scale without allocating a
128×128 framebuffer. The editable source sheet remains in `assets/fox`; run
`node tools/build_fox_assets.js` after changing it.


## WiFi Fox dashboard

The M5Stack screen uses a 128×128 direct-drawn fox, a compact metrics panel and
one yellow RSSI history graph. The previous green packet graph and its buffers
were removed to leave more display and RAM available for monitoring.

The passive analyzer records EAPOL message classes, completed four-way handshake
observations, PMKID KDE records, WPA3/SAE advertisements, WPA2/WPA3 transition
mode and PMF capability. It does not inject frames, alter authentication, or try
passwords. The WPA3 and PMF indicators describe observed advertisements; they do
not prove that an access point is secure.

Host-side parser checks can be run with:

```sh
g++ -std=c++11 -Wall -Wextra -Werror -IESP32-WiFi-Hash-Monster \
  ESP32-WiFi-Hash-Monster/SecurityAnalyzer.cpp tests/security_analyzer_test.cpp \
  -o /tmp/security_analyzer_test && /tmp/security_analyzer_test
```

Use Arduino IDE to compile it, tested with (ESP32 version 1.0.4) M5stack-fire.



# How guess the WiFi password using brute force attack

**Note:** Cracking an WiFi password using brute force attack for a long WiFi password without GPUs or Cloud help, will be a nightmare but if the password is short or you know the key pattern it will be "easily" cracked. 

Here you have a small guide for linux (Ubuntu) to crack the WiFi password using the files stored on the SD_Card of the Purple Hash Monster using your computer.

First we need to install **hashcat**

<pre>
 sudo apt-get update
 sudo apt install hashcat
</pre>

EAPOL/PMKID stored on the SD-Card are *pcap* files, we have to convert to *hccapx* format to work with hashcat. In terminal from the directory were we have the *pcap* file from the SD-CARD:

<pre>
 wget https://raw.githubusercontent.com/hashcat/hashcat-utils/master/src/cap2hccapx.c
 gcc -o cap2hccapx cap2hccapx.c
 ./cap2hccapx 1.pcap 1.hccapx
</pre>

For example if we know that the wifi password has a lenght of 8 digits we can run the following command, and in few seconds we will have the WiFi Password :)

<pre>
 hashcat --force -m 2500 -a 3 -1 ?d -o cracked 1.hccapx ?1?1?1?1?1?1?1?1
</pre>
















