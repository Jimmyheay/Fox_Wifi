# Validação física pendente — M5Stack Core2

Estado: firmware compilado e testes locais aprovados. Nenhuma porta serial ou
placa USB está acessível neste ambiente; os testes abaixo NÃO foram executados.

## Gravação e coleta

No computador ao qual o Core2 está conectado, na raiz do projeto:

```sh
pio run -e m5stack-core2 -t upload --upload-port PORTA
pio device monitor --port PORTA --baud 115200
```

Substitua PORTA pela porta real. O upload do projeto grava os componentes com o
layout correto; firmware.bin isolado é apenas a imagem da aplicação. Guarde o
log serial desde o boot. Não formate nem apague o cartão para testar.

## Critérios de aceitação

1. Iniciar sem microSD: monitor deve permanecer ativo, sem abort/reset; SD deve
   aparecer desabilitado. Tela deve ficar em landscape 320×240 e aceitar botões.
2. Com cartão instalado antes do boot: verificar criação de /pcap, alternância
   de gravação por pressão longa em A e manutenção da interface após desativar SD.
3. Em um AP de teste próprio, fixar o canal e conectar um cliente normalmente.
   Verificar observações M1–M4 e arquivos separados por BSSID. Ausência de PMKID
   não constitui falha: nem toda associação fornece um PMKID observável.
4. Conferir arquivos após desativar a gravação pelo controle e retirar o cartão:
   nomes devem conter SSID sanitizado ou hidden, BSSID, sessão e sequência;
   abrir PCAPs com Wireshark ou tshark, verificando ausência de registros
   truncados, presença dos anúncios e comprimentos EAPOL consistentes.
5. Testar SSID com espaços/caracteres especiais, SSID oculto e dois APs com o
   mesmo SSID. Confirmar arquivos distintos sem sobrescrever capturas anteriores.
6. Alternar canal manual, automático e smart. Verificar canal exibido, respeito
   aos canais regulatórios e permanência limitada após atividade EAPOL.
7. Executar por pelo menos duas horas no ambiente de teste. Registrar tempo,
   condições de tráfego, RX/s, queue_drop, rejected, sd_packets, sd_errors e
   M1/2/3/4. Nenhum reset/panic/WDT é aceitável. Descartes devem ser registrados;
   não há garantia de perda zero. sd_packets conta aceitação em RAM, não
   confirmação física de persistência no cartão.

Tela/touch, integridade elétrica/SPI, desempenho real de recepção e comportamento
do cartão não podem ser certificados por testes de host ou somente por um build.
A ausência de crescimento de heap não pode ser inferida dos contadores atuais:
medição de heap/stack em execução exige instrumentação adicional no dispositivo.
