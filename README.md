**English**
  
# ESP32_AdBlocker  
(This Repo Based on s60sc/ESP32_AdBlocker v3.3.1)  
  
ESP32_AdBlocker acts as a DNS Sinkhole (like [Pi-Hole](https://pi-hole.net)) by returning 0.0.0.0 for any domain names in its blocklist, else uses an external DNS server to resolve IP addresses. This prevents content being retrieved from or sent to blocked domains. A web server is provided to control the service and monitor its operation.  
  
* ESP32-S3 with 8MB PSRAM can host Almost 250k sized blocklist. Blocklist checks take <50 micro seconds.  
  
## Hardware Requirements  
  
ESP32-S3 with 4MB PSRAM Not Supported on My Fork (Using Original)  
  
Please buy ESP32-S3 `N8R8` or `N16R8`  
  
It Work with Seeed XIAO `ESP32-S3 Plus` **16M** but Can't Use Full Space of ROM  
  
If You Use `patitions.csv` for **16M** on `ESP32-S3 Plus`, It Stock on First Boot (Please Use Table for **12M**) (That Provide Enough Space)  
  
Also If You Use ESP32-S3 Plus You Must Change LED Settings in `appGlobals.h`  
  
## Operation  
<img src="extras/webpage.jpg" width="500" height="600">  
  
After power up, the blocklist will be downloaded. It will take several minutes for ESP32_AdBlocker to be ready after processing and sorting the data. Progress can be monitored on the web page. Subsequent reloads of the same file are much quicker as only updates need to be processed.  
As only one file can be downloaded, a consolidated blocklist should be used. You Must select a file less than the size of the PSRAM. The file format should be in either HOSTS format or Adblock format (only domain name entries processed). The following site for example provides a list of suitable files: ~~https://github.com/StevenBlack/hosts~~ https://dns.dateno1.com/hosts.  
  
ESP32_AdBlocker will subsequently download the selected file daily at a given time to keep the blocklist updated. The user can also individually add their own sites to block or unblock which are stored in a local custom blocklist. (Custom BlockList Not Tested on My Fork) (Sorry I'm Too Busy)    
  
The entries on the ESP32_AdBlocker web page are:  
* **Allowed domains**: number of domain requests which have been allowed through since restart  
* **Blocked domains**: number of domain requests which have been blocked since restart  
* **Current URL for blocklist file**: URL for blocklist being used  
* **Enter new URL for blocklist or domain**:  
* **Enter new URL for blocklist or domain**:  
  * After entering new URL for blocklist, press **Reload** button to download, or leave blank to reload current blocklist.  
  * After entering extra domain URL to be blocked, press **AddDomain** button. Not added if a duplicate or not resolvable. Alert message will show result.  
  * After entering existing domain URL to be be removed from blocklist, press **DelDomain** button. Alert message will show result.  
  * After entering domain URL to check if in blocklist, press **CheckDomain** button. Alert message will show result.
* **Stop Blocklist Load**: Press **StopLoad** button to stop the currently downloading blocklist.  
* **Clear custom blocklist**: Clear the custom entries manually added or removed by user  
* **Enable AdBlocker**: Toggle Ad blocking on or off  
  
To make ESP32_AdBlocker your preferred DNS server, enter its IPv4 address in place of the current DNS server IPs in your router / devices. ~~ESP32_AdBlocker does not have an IPv6 address but some devices use IPv6 by default, so disable IPv6 DNS on your device / router to force it to use IPv4 DNS.~~  
Eg for a Windows PC network adapter, to use AdBlocker as DNS Server having IP address `192.168.1.168`, at the Windows command prompt, enter:  
`netsh interface ip set dns "Wi-Fi" static 192.168.1.168`  
To switch back to usual DNS Server, eg Google, enter:  
`netsh interface ip set dns "Wi-Fi" static 8.8.8.8`  
  
Browsers must have **Use secure DNS** disabled as this overrides adapter and router DNS settings.  
  
ESP32_AdBlocker Maybe Not Work Well with Chrome (If It not Worked You Must Block **secure DNS** on Router or Firewall)  
  
--------------------------------------------------------------------------------------------------------------------------------------------
  
## Installation  
  
At First You Need to Download&Install `Arduino IDE`  
  
Download Lastest from Release and Extract that, Change application folder name to 'ESP32_AdBlocker'  
  
Compile using esp32 arduino core min v3.1.1 with PSRAM enabled and the following Partition scheme:  
* ~v1.2 - `8M with spiffs (...)`  
* v1.3~1.4 - `Custom` (If you Using 8M PSRAM Device Using 'Partition_8M.csv' After Rename)  
* v1.5~ - `Custom` (If you Using 8M PSRAM Device Using 'Partition_8M.csv' After Rename) (If You are Using ESP32-S3 Plus Using 'Partition_12M.csv' After Rename)  
  
<img src="extras/IDE%20Settings.png" width="500" height="600">  
~v1.2  
<img src="extras/New%20IDE%20Settings.png" width="500" height="600">  
v1.3~  
Using This Build Option (Don't Change Board Type for ESP32-S3 Plus!)  
  
You Need to Waiting Boot at First Time (UnLike Original Version It ReTry to Connnect SSID and It will Delay AP Mode)  
  
On first installation, the application will start in wifi AP mode - connect to SSID: **ESP32_AdBlocker_...**, to allow router and password details to be entered via the web page on `192.168.4.1`. The configuration data file (except passwords) is automatically created, and the application web pages automatically downloaded from GitHub to the **/data** folder in LittleFS when an internet connection is available.  
  
If You Using It without Internet or Environment that Can't Connect GitHub Upload Files by OTA Menu or WebDAV  
  
To the **/data** folder files, can be made using the **OTA Upload** tab. The **/data** folder can also be reloaded from GitHub using the **Reload /data** button on the **Edit Config** tab, or by using a WebDAV client.  
  
If You Want Debug Using USB Cable, Please Enable 'USB CDC on Boot' option  
  
Test WebDAV failed with Windows Internal Client (You maybe install client for WebDAV)  
  
You Must ReConnect USB Cable after Flashing (Reset by RTS Pin Not Worked at First Time)  
  
--------------------------------------------------------------------------------------------------------------------------------------------
  
## Configuration  
  
More configuration details accessed via **Edit Config** tab, which displays further buttons:  
  
Press **Save** Button to make changes persistent. (It WilL Reboot Device)  
  
* **Network**:  
Additional network and webserver settings.  
  * Device IP + NetMask + Gateway Adress  
  * WireLess Infomation  
  * En/Disable DNS Debug  
  * You Must Set Login ID (Optional user name for web page login) and PW (Optional web page password) (`Security is Not Optional!`)  
  
* **Settings**:  
Environmental settings affecting blocklist operation.  
  
* **Ethernet**:   
Select the Want to Use [Network Type]. To configure Ethernet, define the SPI pin numbers used to connect to the external Ethernet controller.  

* **Status LED**:   
You Can Adjust LED Settings on Web.  
  
--------------------------------------------------------------------------------------------------------------------------------------------  
  
## Network Mode Selection  
  
Default network interface is Wifi, but Ethernet could be used instead using boards with built in Ethernet, or by connecting an external Ethernet controller.  
Feature only tested for W5500 Ethernet controller connected to ESP32S3 board.  
The selected network interface is available after configuration and reboot.  
  
Options:  
* **WiFi** : default  
* **Eth+AP** : Ethernet + ESP Access Point. Do not open web pages on each network concurrently.  
* **Ethernet**: Ethernet only, no Wifi  
  
**Warning : Ethernet Not Tested on This Repo**  
  
--------------------------------------------------------------------------------------------------------------------------------------------  

* **LED**:   
  
LED Brightness : 16  
Adjust Brightness If You Want (0 = Off)  
LED GPIO pin : 48  
If You are Using `ESP32-S3 Plus` Change It to **21**  
LED Type : WS2812  
If You are Using `ESP32-S3 Plus` Change It to **Plain GPIO**  
  
`RGB Mode`  
AP Mode : Yellow  
Normal : Green  
Offline : Cyan  
Failed : Red Blink  
hosts Downloading : Blue Blink  
No Internet and Try hosts Download : Purple Blink  
  
`Simple (Single Color) Mode` (Mode for No RGB LED like ESP32-S3 Plus)  
AP Mode&Normal : Solid  
Offline : Slow Blink  
hosts Downloading : Fast Blink  
Failed : Very Fast Blink  
  
--------------------------------------------------------------------------------------------------------------------------------------------  
  
## Log
  
The application log messages can be monitored on the web page tab **Show Log**.  
  
The **Verbose** button will reveal extra logging for each blocked or accepted connection.  
  
If You Want Debug Using USB Cable, Use 'pio device monitor --baud 115200' (If You are Using Windows Run '"%AppData%\Python\Python314\Scripts\pio.exe" device monitor --baud 115200')  
  
You Need to Install Python for pio Command  
  
============================================================
  
한국어 (일부 문장은 기계 번역되었습니다)  
  
# ESP32_AdBlocker  
(이 Repo는 s60sc/ESP32_AdBlocker v3.3.1에 기반을 두고 있습니다)  
  
ESP32_AdBlocker는 차단 목록에 포함된 도메인 이름에 대해 `0.0.0.0`을 반환함으로써 ([Pi-Hole](https://pi-hole.net)과 같은) DNS 싱크홀(DNS Sinkhole) 역할을 수행하며, 그 외의 경우에는 외부 DNS 서버를 사용하여 IP 주소를 확인합니다. 이를 통해 차단된 도메인으로 데이터를 전송하거나 해당 도메인에서 콘텐츠를 가져오는 것을 방지합니다. 또한, 서비스 제어 및 작동 상태 모니터링을 위한 웹 서버 기능도 제공합니다.  
  
* 8MB PSRAM을 가진 ESP32-S3는 거의 25만개의 차단 목록을 제공할 수 있습니다. 차단 목록의 확인에는 50ms 이하의 시간이 소비됩니다  
  
## 하드웨어 요구 사항  
  
PSRAM 4M의 ESP32은 이 Fork에서 지원되지 않으므로 오리지널을 써주세요  
  
ESP32-S3 `N8R8`나 `N16R8`를 구매해주세요  
  
Seeed XIAO `ESP32-S3 Plus` **16M**에서도 작동합니다만, ROM의 전체를 쓸 수 없습니다  
  
만일 `ESP32-S3 Plus`에서 **16M**용 `patitions.csv`를 사용할 경우 첫 부트에서 멈춥니다 (**12M**용 테이블을 써주세요) (그걸로도 충분한 공간이 제공됩니다)  
  
또한 ESP32-S3 Plus를 사용한다면 `appGlobals.h`의 LED 설정도 변경해야합니다  
  
## 작동  
<img src="extras/webpage.jpg" width="500" height="600">  
  
전원을 켜면 차단 목록이 다운로드됩니다. 데이터를 처리하고 분류하는 과정을 거쳐 ESP32_AdBlocker가 준비되기까지는 수 분이 소요됩니다. 진행 상황은 웹 페이지에서 확인할 수 있습니다. 이후 동일한 파일을 다시 불러올 때는 업데이트된 내용만 처리하면 되므로 훨씬 빠르게 진행됩니다.  
  
한 번에 하나의 파일만 다운로드할 수 있으므로 통합된 차단 목록(consolidated blocklist)을 사용해야 합니다. 반드시 PSRAM 용량보다 작은 파일을 선택하는 것이 좋습니다. 파일 형식은 HOSTS 또는 Adblock 형식이어야 합니다(도메인 이름 항목만 처리됨). 예를 들어, 다음 사이트에서 적합한 파일 목록을 제공합니다: ~~https://github.com/StevenBlack/hosts~~ https://dns.dateno1.com/hosts.  
  
ESP32_AdBlocker는 차단 목록을 최신 상태로 유지하기 위해 지정된 시간에 매일 선택한 파일을 다운로드합니다. 또한 사용자가 차단하거나 차단 해제할 사이트를 개별적으로 추가할 수 있으며, 이는 로컬 Custom BlockList에 저장됩니다. (이 Fork에서는 Custom BlockList이 시험되지 않았습니다)  
  
ESP32_AdBlocker 웹 페이지의 항목은 다음과 같습니다.  
* **Allowed domains**: 재시작 이후 허용된 도메인 요청 수  
* **Blocked domains**: 재시작 이후 차단된 도메인 요청 수  
* **Current URL for blocklist file**: 사용 중인 차단 목록의 URL  
* **Enter new URL for blocklist or domain**:  
  * 새 URL을 입력한 후 **Reload** 버튼을 눌러 새로운 BlockList를 다운로드하거나, 빈칸으로 두고 눌러서 현재 차단 목록을 다시 받을 수 있습니다.  
  * 차단할 추가 도메인 URL을 입력한 후 **AddDomain** 버튼을 누르세요. 중복되거나 도메인 해석(resolving)이 불가능한 경우에는 추가되지 않으며, 결과는 알림 메시지로 표시됩니다.  
  * BlockList에서 삭제할 기존 도메인 URL을 입력한 후 **DelDomain** 버튼을 누르세요. 알림 메시지를 통해 결과를 확인할 수 있습니다.  
  * 차단 목록 포함 여부를 확인하려는 도메인 URL을 입력한 후 **CheckDomain** 버튼을 누르세요. 알림 메시지를 통해 결과를 확인할 수 있습니다.  
* **Stop Blocklist Load***: **StopLoad** 버튼을 눌러 현재 다운로드 중인 차단 목록 로드를 중지할 수 있습니다  
* **Clear custom blocklist**: 사용자가 수동으로 추가한 Custom BlockList을 삭제합니다.  
* **Enable AdBlocker**: 광고 차단을 켜고 끕니다  
  
ESP32_AdBlocker를 기본 DNS 서버로 설정하려면, 공유기나 기기의 기존 DNS 서버 IP 주소 대신 ESP32_AdBlocker의 IPv4 주소를 입력하십시오. ~~ESP32_AdBlocker는 IPv6 주소를 지원하지 않지만, 일부 기기는 기본적으로 IPv6를 사용하므로, 기기나 공유기에서 IPv6 DNS를 비활성화하여 IPv4 DNS를 사용하도록 설정해야 합니다.~~  
예를 들어, IP 주소가 `192.168.1.168`인 AdBlocker를 DNS 서버로 사용하도록 Windows PC 네트워크 어댑터를 설정하려면 Windows 명령 프롬프트에 다음을 입력하십시오.  
`netsh interface ip set dns "Wi-Fi" static 192.168.1.168`  
Google과 같은 일반 DNS 서버로 다시 전환하려면 다음을 입력하세요.  
`netsh interface ip set dns "Wi-Fi" static 8.8.8.8`  
  
브라우저의 **보안 DNS 사용(Use secure DNS)** 설정은 비활성화해야 합니다. 이 설정이 활성화되면 어댑터 및 라우터의 DNS 설정이 무시되기 때문입니다.  

ESP32_AdBlocker는 크룸에서 제대로 작동하지 않을 수 있습니다 (만일 작동하지 않는 경우 반드시 **secure DNS**를 라우터나 방화벽에서 차단해야 합니다)  
  
--------------------------------------------------------------------------------------------------------------------------------------------
  
## 설치  
  
가장 먼저 `Arduino IDE`를 설치해주세요  
  
GitHub Release의 최신 버전을 받아서 압축 해제후 폴더 이름을 'ESP32_AdBlocker'로 변경해주세요  
  
ESP32 Arduino Core v3.1.1이상 버전을 설치후 PSRAM 활성화하고, 다음 파티션 구조로 설정해주세요   
* v1.2 이하 `8M with spiffs (...)`  
* v1.3~1.4 `Custom` (만일 8M PSRAM 기종을 쓰신다면 'Partition_8M.csv'를 이름 변경해서 써주세요)  
* v1.5 이상 `Custom` (만일 8M PSRAM 기종을 쓰신다면 'Partition_8M.csv'를 이름 변경해서 써주세요) (만일 ESP32-S3 Plus를 쓰신다면 'Partition_8M.csv'를 이름 변경해서 써주세요)  
  
<img src="extras/IDE%20Settings.png" width="500" height="600">  
~v1.2  
<img src="extras/New%20IDE%20Settings.png" width="500" height="600">  
v1.3~  
위 빌드 옵션을 써주세요 (ESP32-S3 Plus에서 보드 타입 변경 금지!)  
  
초회에는 부팅 완료를 기다릴 필요가 있습니다 (오리지널 버전과는 달리 SSID 연결 재시도를 하므로 AP Mode가 지연됩니다)  
  
최초 설치시 Wifi AP Mode로 실행되니 **ESP32_AdBlocker_...** 패턴의 SSID에 접속하여 192.168.4.1을 브라우저로 접속후 무선 정보를 입력해주세요. 설정 파일 (비번 제외)이 자동으로 생성된후 자동으로 GitHub에서 LittleFS의 **/data** 폴더에 자동으로 웹페이지가 받아집니다  
  
만일 인터넷이 안 되거나 GitHub에 접속이 불가능한 환경에서 사용하신다면 OTA Menu나 WebDAV로 파일들을 올려주세요  
  
**/data** 폴더를 변경하실려면 **OTA Upload** 텝이나 WebDAV 클라를 사용해주세요. 해당 폴더는 **Edit Config** 텝의 **Reload /data** 버튼을 누르는것으로 재설정이 가능합니다  
  
USB Cable로 디버그를 하길 원하신다면 'USB CDC on Boot'옵션을 활성화해주세요  
  
Windows 내장 WebDAV 클라로 시험했을떄 작동 실패하였습니다 (WebDAV 클라를 별도로 설치해야 합니다)  
  
플레싱후 케이블을 탈착해야 합니다 (RTS Pin을 사용한 재부팅이 초회에는 작동하지 않습니다)  
  
--------------------------------------------------------------------------------------------------------------------------------------------
  
## 설정  
  
**Edit Config** 탭을 통해 추가적인 구성 세부 사항에 접근할 수 있으며, 이 탭에는 다음과 같은 버튼들이 표시됩니다.  

**Save** 버튼을 눌러야 변경 사항이 적용됩니다 (장치가 재부팅됩니다)  
  
* **Network**:  
추가적인 네트워크 및 웹 서버 설정  
  * 장치 IP + NetMask + Gateway 주소  
  * 무선 정보  
  * DNS 디버그 (비)활성화  
  * 반드시 로그인 ID (Optional user name for web page login)및 비번 (Optional web page password)을 설정해주세요 (`보안은 옵션이 아닙니다!`)  
  
* **Settings**:  
차단 목록 적용에 영향을 주는 환경 설정들  
  
* **Ethernet**:   
사용하고싶은 [네트워크 타입]을 선택해주세요. 이더넷을 구성하려면 외부 이더넷 컨트롤러 연결에 사용할 SPI 핀 번호를 지정해야 합니다.  

* **Status LED**:   
웹에서 LED 설정을 변경 가능합니다.  
  
--------------------------------------------------------------------------------------------------------------------------------------------  
  
## 네트워크 모드 선택  
  
기본 네트워크 인터페이스는 Wi-Fi지만, 이더넷 기능이 내장된 보드를 사용하거나 외부 이더넷 컨트롤러를 연결하여 이더넷을 사용할 수 도 있습니다.  
이 기능은 ESP32S3 보드에 연결된 W5500 이더넷 컨트롤러에 대해서만 테스트되었습니다.  
선택한 네트워크 인터페이스는 설정 및 재부팅 후 사용할 수 있습니다.  
  
Options:  
* **WiFi** : 기본값  
* **Eth+AP** : 유선 및 ESP AP . 각 네트워크에서 웹 페이지를 동시에 열지 마십시오.  
* **Ethernet**: 유선 전용, 무선 미사용  
  
**경고 : 이 Repo는 유선이 시험되지 않았습니다**  
  
--------------------------------------------------------------------------------------------------------------------------------------------  
  
* **LED**:   
  
LED Brightness : 16  
원하는 밝기로 조정해주세요 (0 = 꺼짐)  
LED GPIO pin : 48  
만일 `ESP32-S3 Plus`를 쓰신다면 이걸 **21**로 변경해주세요  
LED Type : WS2812  
만일 `ESP32-S3 Plus`를 쓰신다면 이걸 **Plain GPIO**로 변경해주세요    
  
`RGB Mode`  
AP 모드 : 황색  
정상 : 녹색  
오프라인 : 청록색  
실패 : 빨간색 점멸  
hosts 다운로드중 : 청색 점멸  
인터넷이 안 되는 상태에서 hosts 다운로드 시도 : 보라색 점멸  
  
`간이 (단색) 모드` (RGB LED가 없는 ESP32-S3 Plus같은 기기를 위한 모드)  
AP 모드&정상 : 켜짐  
오프라인 : 천천히 깜빡임  
hosts 다운로드중 : 빠르게 깜빡임  
실패 : 매우 빠르게 깜빡임  
  
--------------------------------------------------------------------------------------------------------------------------------------------  
  
## 기록
  
애플리케이션 로그 메시지는 웹 페이지의 **Show Log** 탭에서 모니터링할 수 있습니다.  
  
**Verbose** 버튼을 클릭하면 차단되거나 허용된 각 연결에 대한 상세 로그가 표시됩니다.  
  
USB Cable로 디버그를 하길 원하신다면 'pio device monitor --baud 115200'를 사용해주세요 (만일 Windows를 사용중이라면 '"%AppData%\Python\Python314\Scripts\pio.exe" device monitor --baud 115200' 형식을 사용해주세요)  
  
pio 명령을 쓰기 위해서는 Python을 설치할 필요성이 있습니다  
  
