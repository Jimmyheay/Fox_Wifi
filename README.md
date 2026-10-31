# Fox WiFi

<p align="center">
    <a href="https://github.com/Jimmyheay/Fox_Wifi/blob/main/LICENSE"><img alt="Software License" src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>
    <a href="https://github.com/Jimmyheay/Fox_Wifi/graphs/contributors"><img alt="Contributors" src="https://img.shields.io/github/contributors/Jimmyheay/Fox_Wifi"/></a>
</p>

Fox WiFi passively records 802.11 packets to a microSD card on M5Stack and ESP32 hardware.

Most of the code is based on the excellent [PacketMonitor32](https://github.com/spacehuhn/PacketMonitor32/) by &nbsp; <a href="https://twitter.com/intent/follow?screen_name=spacehuhn"><img src="https://img.shields.io/twitter/follow/spacehuhn?style=social&logo=twitter" alt="Follow on Twitter"></a>, together with the [M5Stack](https://m5stack.com/) port by [macsbug](https://macsbug.wordpress.com/2018/01/11/packetmonitor32-with-m5stack/). The project explores how a compact ESP32 device can present network-monitoring information inspired by [Pwnagotchi](https://github.com/evilsocket/pwnagotchi) <a href="https://twitter.com/intent/follow?screen_name=pwnagotchi"><img src="https://img.shields.io/twitter/follow/pwnagotchi?style=social&logo=twitter" alt="Follow on Twitter"></a>.

![Fox WiFi Edition interface](./assets/readme/fox-wifi-edition.png)

When a Wi-Fi client connects to a WPA2-PSK access point, the devices exchange four EAPOL messages as part of the four-way handshake. Fox WiFi records observed EAPOL and PMKID-related traffic for authorized, offline analysis.

Fox WiFi captures EAPOL and PMKID observations to the microSD card for later analysis.

Short-press the first button to enable Incognito mode, which turns off the display and LEDs. Long-press it to enable or disable microSD storage for captured EAPOL and PMKID traffic.

Short-press the second button to change the display backlight brightness. Long-press it to change the LED bar brightness.

Short-press the third button to change the Wi-Fi channel. Long-press it to select **Auto-Channel** or **Smart-Channel** mode.

**Auto-Channel** cycles through channels 1 through 13 every 15 seconds.

**Smart-Channel** scans all channels in sequence, changing channels only when no new SSID, EAPOL, or deauthentication frame is observed for 15 seconds.

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
bash tools/test_host.sh
# AddressSanitizer + UndefinedBehaviorSanitizer:
SANITIZE=1 bash tools/test_host.sh
# Neste executor, LeakSanitizer não funciona sob ptrace:
ASAN_OPTIONS=detect_leaks=0 SANITIZE=1 bash tools/test_host.sh
```

## M5Stack Core2

`m5stack-core2` is the default PlatformIO environment. The dashboard forces the
Core2 display into 320×240 landscape, uses Chimera-Core's Core2 display and
button API, and keeps passive monitoring active when no microSD card is present.
Without a card, capture storage is disabled until the SD control is enabled;
screen metrics and channel controls remain available.

Build it with:

```sh
pio run -e m5stack-core2
```

The M5Stack Fire environment remains available as `m5stack-fire`.

The validated Core2 build uses PlatformIO Core 6.1.19, Espressif32 6.5.0 and
Arduino-ESP32 2.0.14 (ESP-IDF 4.4.6). `platformio.ini` pins LovyanGFX 1.2.35,
ESP32-Chimera-Core 1.5.2, M5Stack-SD-Updater 1.2.8 and ESP32-targz 1.3.1.

Arduino 2.0.0 lacks SPI definitions required by this LovyanGFX version. Chimera
1.5.2 selects an unavailable I2S header with Arduino 2.0.17, so upgrading the SDK
alone does not resolve compatibility. The project also exports
`include/utility/miniz.h` to dependency compilation: it forwards Chimera's old
header name to LovyanGFX's real `lgfx_miniz.h`. Downloaded libraries are unchanged.
Keep this header and the `build_flags` include path when building elsewhere.

The firmware compiles and links for Core2. Other board targets and execution on
physical hardware have not been validated. PlatformIO is the tested build path;
Arduino IDE additionally needs the compatibility include directory exported to
library compilation and has not been tested.



# Capture workflow

Use these commands only with networks and capture files that you are authorized to assess.

## Convert PCAP

```sh
tshark -r 0006.pcap -w 0006_novo.pcapng -F pcapng
sudo hcxpcapngtool -o hash_total2.txt 0006_novo.pcapng
```

## Inspect EAPOL

```sh
tshark -r 0006.pcap -Y "eapol"
```

## Convert for Hashcat

```sh
hcxpcapngtool -o hash_total.txt arquivo_captura.pcapng
```

## Hashcat

```sh
hashcat -m 22000 -a 0 hash_total.txt /usr/share/wordlists/rockyou.txt
```

## Hashcat — 8 digits

```sh
hashcat -m 22000 -a 3 01-hash/hash_total.txt "?d?d?d?d?d?d?d?d"
```

















## Refatoração de captura e armazenamento

A aplicação completa fica em `ESP32-WiFi-Hash-Monster/CaptureApp.cpp`.
O `.ino` é o ponto de entrada do Arduino IDE; a implementação em C++ evita
problemas do gerador de protótipos do Arduino. O alvo é Arduino-ESP32
2.0.14, conforme `platformio.ini`; a API de WDT do Arduino-ESP32 3.x é diferente.
O fluxo de compilação validado é PlatformIO, com `pio run -e m5stack-core2`.
No Arduino IDE, além das bibliotecas fixadas e do Core ESP32 2.0.14, é necessário
exportar o caminho `include/` do projeto para a compilação das bibliotecas.

- O callback roda na tarefa Wi-Fi do ESP-IDF, **não em uma ISR**. Ele filtra e
  copia quadros para uma fila SPSC estática de 16 posições, sem I/O nem heap.
  Quatro posições ficam reservadas para EAPOL e associação/reassociação. A fila
  ocupa aproximadamente 40 KiB de RAM interna e contabiliza descartes. A versão
  de 32 posições excedia o limite de DRAM estática na etapa de link do Core2;
  a redução evita esse excesso sem alocações no callback. Isso reduz a capacidade
  de absorver rajadas; não há garantia de ausência de perdas.
- A tarefa consumidora tem prioridade 2 no núcleo 1; Wi-Fi fica no núcleo 0.
  Parsing, TFT e SD têm um único proprietário, evitando disputa entre tarefas
  pelo SPI. A tarefa cede a CPU a cada iteração e assina o task watchdog,
  preservando uma configuração existente. Falhas de inicialização são exibidas
  pela serial em vez de provocar `ESP_ERROR_CHECK`/abort.
- Os parsers validam Frame Control, LLC/SNAP completo, QoS/HT Control, direção
  AP/cliente, comprimentos EAPOL e limites de IEs. Quadros protegidos,
  fragmentados, WDS/IBSS e A-MSDU não são decodificados. Recepção com erro,
  MPDUs maiores que 2500 bytes e quadros truncados são descartados. O FCS de
  quatro bytes é removido de management **e** data conforme `sig_len` do ESP-IDF.
- PMKIDs são observados no KDE não criptografado e nas listas RSN válidas de
  associação/reassociação e anúncios. Não há busca indiscriminada por bytes.
  PMKID não é garantido, nem se restringe a um frame de associação enviado
  pelo AP. PBKDF2 deriva a PMK em WPA2-Personal; PMKID é outro identificador.
- O contador HANDSHAKE exige M1→M2→M3→M4 do mesmo AP/cliente em até dez segundos
  entre etapas, replay counters coerentes e ANonce igual em M1/M3. Retentativas
  não contam uma nova conclusão. Essa contagem é conservadora: observar quatro
  mensagens não valida criptograficamente o MIC. Os quatro quadros válidos são
  gravados mesmo quando chegaram fora de ordem ou o contador não fecha.
- O cache usa hash e comporta 128 BSSIDs. Ao encher, entradas são substituídas;
  contagens de AP/capacidades podem incluir revisitas após substituição.
  PMKID é uma contagem de observações, incluindo retransmissões, não de valores
  únicos nem de credenciais recuperáveis.

Os arquivos ficam em `/pcap`, por exemplo:

```text
Minha_Rede_001122334455_89abcdef_00000001.pcap
hidden_001122334455_89abcdef_00000002.pcap
```

SSID é tratado como até 32 **octetos**, incluindo NUL e bytes não UTF-8. O nome
usa somente letras ASCII, números, `_` e `-`, sempre acompanhado do BSSID
completo, identificador de sessão e sequência. O nome é escolhido na primeira
gravação: se o SSID ainda era desconhecido, permanece `hidden` nessa sessão.
Não se renomeiam arquivos abertos quando um SSID oculto é revelado posteriormente.

Há três handles abertos com buffers de 4 KiB. Quando um handle é substituído,
seu buffer é drenado e o mesmo arquivo da sessão é reaberto em append ao rever
o BSSID, preservando M1–M4 juntos. Substituição de uma entrada no cache de 128
BSSIDs inicia outro arquivo. Os arquivos existentes nunca são sobrescritos.
Os buffers são drenados/sincronizados a cada segundo e no desligamento lógico
da captura. Escritas parciais e falhas de abertura desabilitam a gravação;
a monitoração continua. A serial expõe descartes de fila, rejeições estruturais,
quadros aceitos pelo buffer SD, erros SD e observações M1/M2/M3/M4. Contar um
quadro aceito no buffer não garante persistência física.

PCAP usa DLT_IEEE802_11 (105), sem FCS ou radiotap; timestamps são microssegundos
monotônicos desde o boot, **não hora UTC**. Beacons/probe responses são guardados
na primeira observação, ao descobrir o SSID e periodicamente a cada 15 segundos;
associação/reassociação e EAPOL válidos são mantidos. Sem beacon/SSID observado,
o PCAP pode precisar de contexto adicional para análise. Não são gravados todos
os pacotes de dados da rede. Desligamento abrupto pode perder dados ainda em RAM;
uma falha física durante escrita pode deixar o último registro incompleto.

O hopping respeita os canais retornados pela configuração regulatória do driver
(limitados a 1–13). Não força um país diferente. Após EAPOL no canal atual,
a troca automática aguarda até cinco segundos de silêncio, com limite total de
20 segundos por permanência; anúncios e storms de deauth não prendem o canal.
O modo smart também dá esse tempo limitado a SSIDs recém-descobertos. Para acompanhar
uma rede específica, use canal fixo: um único rádio ESP32 de 2,4 GHz não consegue
ouvir todos os canais simultaneamente, nem recebe 5/6 GHz. Nenhum firmware pode
garantir captura de M1–M4, ausência de perdas ou recuperação de senha.

Os testes locais verificam layouts de quadro, limites, PMKIDs, correlação de
handshake, concorrência da fila, bytes PCAP, append após substituição de handles,
reabertura e falhas SD simuladas. Eles não substituem testes no M5Stack Core2
com rádio e cartão reais. A compilação PlatformIO do Core2 foi concluída,
incluindo link e geração de `.pio/build/m5stack-core2/firmware.bin`. O uso estático
reportado foi de 120.780 bytes de RAM e 1.038.733 bytes de flash. O percentual de
RAM exibido pelo PlatformIO inclui PSRAM e não representa a folga de DRAM interna;
heap disponível em execução e estabilidade no hardware ainda não foram medidos.
