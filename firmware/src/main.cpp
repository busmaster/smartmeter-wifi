#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <AsyncElegantOTA.h>
#include <SPIFFS.h>

#include <espMqttClient.h>

#include "esp_system.h"
#include "esp_log.h"
#include "esp_err.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "aes.h"
#include "usb/usb.h"


/* MBUS telegram */
#define METER_TELEGRAM_SIZE                 101
#define SEARCH_ACK   0xe5

/* byte offsets of MBUS */
#define MBUS_ACCESS_NUMBER_OFFS             15
#define MBUS_PAYLOAD_OFFS                   19
#define MBUS_PAYLOAD_SIZE                   80
#define MBUS_CHECKSUM_OFFS                  99

/* checksum range */
#define MBUS_CHECKSUM_START_OFFS            4
#define MBUS_CHECKSUM_END_OFFS              98

#define AES_KEY_LEN                         16
#define AES_IV_LEN                          16


static AsyncWebServer server(80);
static AsyncWebSocket ws("/ws");

//Variables to save values from HTML form
static String aeskey;
static String smartmeter_html;
static String mqttbroker;
static int    mqttport;
static String mqtttopic;
static String mqtt_html;
static String ssid;
static String pass;
static String wlan_html;

// File paths to save input values permanently
static const char* ssidPath = "/ssid.txt";
static const char* passPath = "/pass.txt";
static const char* aeskeyPath = "/aeskey.txt";
static const char* mqttbrokerPath = "/mqttbroker.txt";
static const char* mqttportPath = "/mqttport.txt";
static const char* mqtttopicPath = "/mqtttopic.txt";

static espMqttClient mqttClient;
static bool reconnectMqtt;
static uint32_t lastReconnectMqttMs;

static uint32_t lastReconnectWifiMs;

// Set LED GPIO
static const int ledPin = 37;
static int ledState = 0;

static unsigned char aesKeyArray[AES_KEY_LEN];

static uint32_t pplus;
static uint32_t pminus;
static uint32_t aplus;
static uint32_t aminus;
static uint32_t qplus;
static uint32_t qminus;
static uint32_t rplus;
static uint32_t rminus;

static bool usbRxInSync;
static tx_func usbTx;

static void WsNotifyClients(const char *name, uint32_t val) {
    char json[50];
    snprintf(json, sizeof(json), "{\"name\":\"%s\", \"value\":\"%u\"}", name, val);
    ws.textAll(json);
}

static void UsbNewDev(void *hdl) {

    usbRxInSync = false;
}

static bool UsbRx(const uint8_t *data, size_t dataLen, void *arg)
{
    static uint8_t searchSeq[] = { 0x10, 0x40, 0xf0, 0x30, 0x16 }; /* SND_NKE for 240 */
    static uint8_t payload[MBUS_PAYLOAD_SIZE];
    /* lower half of iv is the secondary address - it's the same for all EAG meters */
    static unsigned char iv[AES_IV_LEN]  = { 0x2d, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    bool sendReq = false;
    bool ret = false;
    uint8_t checksum;
    int i;

    if (!usbRxInSync) {
        if (dataLen < sizeof(searchSeq)) {
            return false;
        } if (dataLen > sizeof(searchSeq)) {
            return true;
        }
    }

    if (ledState == 0) {
        digitalWrite(ledPin, HIGH);
        ledState = 1;
    }

    if ((dataLen == sizeof(searchSeq)) && (memcmp(searchSeq, data, sizeof(searchSeq)) == 0)) {
        sendReq = true;
        ret = true;
        usbRxInSync = true;
    } else if (dataLen == METER_TELEGRAM_SIZE) {
        ret = true;
        sendReq = true;
        checksum = 0;
        for (i = MBUS_CHECKSUM_START_OFFS; i <= MBUS_CHECKSUM_END_OFFS; i++) {
            checksum += data[i];
        }
        if (checksum == data[MBUS_CHECKSUM_OFFS]) {
            /* set upper half of iv */
            for (i = 8; i < 16; i++) {
                iv[i] = data[MBUS_ACCESS_NUMBER_OFFS];
            }
            AES128_CBC_decrypt_buffer(payload, (uint8_t *)&data[MBUS_PAYLOAD_OFFS], sizeof(payload), aesKeyArray, iv);

            pplus =  (uint32_t)payload[44] | ((uint32_t)payload[45] << 8) | ((uint32_t)payload[46] << 16) | ((uint32_t)payload[47] << 24);
            pminus = (uint32_t)payload[51] | ((uint32_t)payload[52] << 8) | ((uint32_t)payload[53] << 16) | ((uint32_t)payload[54] << 24);
            qplus =  (uint32_t)payload[58] | ((uint32_t)payload[59] << 8) | ((uint32_t)payload[60] << 16) | ((uint32_t)payload[61] << 24);
            qminus = (uint32_t)payload[66] | ((uint32_t)payload[67] << 8) | ((uint32_t)payload[68] << 16) | ((uint32_t)payload[69] << 24);
            aplus =  (uint32_t)payload[12] | ((uint32_t)payload[13] << 8) | ((uint32_t)payload[14] << 16) | ((uint32_t)payload[15] << 24);
            aminus = (uint32_t)payload[19] | ((uint32_t)payload[20] << 8) | ((uint32_t)payload[21] << 16) | ((uint32_t)payload[22] << 24);
            rplus =  (uint32_t)payload[28] | ((uint32_t)payload[29] << 8) | ((uint32_t)payload[30] << 16) | ((uint32_t)payload[31] << 24);
            rminus = (uint32_t)payload[38] | ((uint32_t)payload[39] << 8) | ((uint32_t)payload[40] << 16) | ((uint32_t)payload[41] << 24);

            ESP_LOGD(TAG, "P+: %d W", pplus);
            ESP_LOGD(TAG, "P-: %d W", pminus);
            ESP_LOGD(TAG, "A+: %d Wh", aplus);
            ESP_LOGD(TAG, "A-: %d Wh", aminus);
            ESP_LOGD(TAG, "Q+: %d var", qplus);
            ESP_LOGD(TAG, "Q-: %d var", qminus);
            ESP_LOGD(TAG, "R+: %d varh", rplus);
            ESP_LOGD(TAG, "R-: %d varh", rminus);

            if (mqttClient.connected()) {
                char message[256];
                snprintf(message, sizeof(message), 
                    "{\"counter\":{\"A+\":%u,\"A-\":%u,\"R+\":%u,\"R-\":%u},\"power\":{\"P+\":%u,\"P-\":%u,\"Q+\":%u,\"Q-\":%u}}",
                    aplus, aminus, rplus, rminus, pplus, pminus, qplus, qminus);
                mqttClient.publish(mqtttopic.c_str(), 1, true, message);
            }
            if (ws.availableForWriteAll()) {
                WsNotifyClients("pplus",  pplus);
                WsNotifyClients("pminus", pminus);
                WsNotifyClients("aplus",  aplus);
                WsNotifyClients("aminus", aminus);
                WsNotifyClients("qplus",  qplus);
                WsNotifyClients("qminus", qminus);
                WsNotifyClients("rplus",  rplus);
                WsNotifyClients("rminus", rminus);
            }
        } else {
            usbRxInSync = false;
            Serial.printf("checksum error\r\n");
        }
    } else if (dataLen > METER_TELEGRAM_SIZE) {
        usbRxInSync = false;
        ret = true;
    }

    if (sendReq) {
        const uint8_t buf[] = { 0x05, SEARCH_ACK };
        if (usbTx) {
            usbTx(arg, buf, sizeof(buf), 100);
        }
        digitalWrite(ledPin, LOW);
        ledState = 0;
    }

    return ret;
}

// Read File from SPIFFS
static String readFile(fs::FS &fs, const char * path) {
  
    Serial.printf("Reading file: %s\r\n", path);

    File file = fs.open(path);
    if (!file || file.isDirectory()) {
        Serial.println("- failed to open file for reading");
        return String();
    }
  
    String fileContent;
    while (file.available()) {
        fileContent = file.readString();
        break;     
    }
    file.close();
   
    return fileContent;
}

// Write file to SPIFFS
static void writeFile(fs::FS &fs, const char *path, const char *message) {

    Serial.printf("Writing file: %s\r\n", path);

    File file = fs.open(path, FILE_WRITE);
    if (!file) {
        Serial.println("- failed to open file for writing");
        return;
    }

    if (file.print(message)){
        Serial.println("- file written");
    } else {
        Serial.println("- write failed");
    }
    file.close();
}


static void InitWiFi() {

    char ssid_ap[5 /* 'smif-' */ + 16 /* max uint64_t hex string length */ + 1 /* 0 term */];

    WiFi.mode(WIFI_MODE_APSTA /*WIFI_STA*/);
    snprintf(ssid_ap, sizeof(ssid_ap), "smif-%llx", ESP.getEfuseMac());
    WiFi.softAP(ssid_ap, "smifwifi");
    IPAddress IP = WiFi.softAPIP();
    Serial.print("AP IP address: ");
    Serial.println(IP);

    if (!ssid.isEmpty() && !pass.isEmpty()) {
        WiFi.begin(ssid.c_str(), pass.c_str());

        Serial.println("Connecting to WiFi...");
        unsigned long currentMillis = millis();
        unsigned long startMillis = currentMillis;
        while (WiFi.status() != WL_CONNECTED) {
            currentMillis = millis();
            if ((currentMillis - startMillis) >= 10000) {
                Serial.println("Failed to connect.");
                return;
            }
        }
        Serial.print("IP address: ");
        Serial.println(WiFi.localIP());
    }
}

static void Set_key(String aeskey) {

    char str[48];
    int i = 0;
    snprintf(str, sizeof(str), "%s", aeskey.c_str());
    char *tok = strtok(str, " ");
    while ((i < sizeof(aesKeyArray)) && (tok != 0)) {
        aesKeyArray[i] = (uint8_t)strtoul(tok, 0, 16);
        i++;
        tok = strtok(0, " ");
    }
}

static void ConnectToMqtt(void) {
    Serial.println("Connecting to MQTT...");
    if (!mqttClient.connect()) {
        reconnectMqtt = true;
        lastReconnectMqttMs = millis();
        Serial.println("Connecting failed.");
    } else {
        reconnectMqtt = false;
    }
}

static void OnMqttConnect(bool sessionPresent) {
    Serial.println("Connected to MQTT.");
    Serial.print("Session present: ");
    Serial.println(sessionPresent);
}

static void OnMqttDisconnect(espMqttClientTypes::DisconnectReason reason) {
    Serial.printf("Disconnected from MQTT: %u.\n", static_cast<uint8_t>(reason));

    if (WiFi.isConnected()) {
        reconnectMqtt = true;
        lastReconnectMqttMs = millis();
    }
}

static void OnEvent(AsyncWebSocket *server, AsyncWebSocketClient *client, AwsEventType type,
             void *arg, uint8_t *data, size_t len) {
    switch (type) {
    case WS_EVT_CONNECT:
        Serial.printf("WebSocket client #%u connected from %s\n", client->id(), client->remoteIP().toString().c_str());
        break;
    case WS_EVT_DISCONNECT:
        Serial.printf("WebSocket client #%u disconnected\n", client->id());
        break;
    case WS_EVT_DATA:
    case WS_EVT_PONG:
    case WS_EVT_ERROR:
        Serial.printf("WebSocket WS_EVT_DATA WS_EVT_ERROR WS_EVT_PONG\r\n");
        break;
   }
}

void initWebSocket() {
  ws.onEvent(OnEvent);
  server.addHandler(&ws);
}

String processor(const String& var){
  if (var == "PPLUS"){
    return String(pplus);
  } else if (var == "PMINUS"){
    return String(pminus);
  } else if (var == "QPLUS"){
    return String(qplus);
  } else if (var == "QMINUS"){
    return String(qminus);
  } else if (var == "APLUS"){
    return String(aplus);
  } else if (var == "AMINUS"){
    return String(aminus);
  } else if (var == "RPLUS"){
    return String(rplus);
  } else if (var == "RMINUS"){
    return String(rminus);
  }
  return String();
}

static void RouteWebpages(void) {

    // Route for root / web page
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (ON_STA_FILTER(request)) {
            request->send(SPIFFS, "/index.html", "text/html", false, processor);
        } else if (ON_AP_FILTER(request)) {
            request->send(200, "text/html", wlan_html);
        }
    });

    server.on("/", HTTP_POST, [](AsyncWebServerRequest *request) {
        if (ON_AP_FILTER(request)) {
            int params = request->params();
            for (int i = 0; i < params; i++) {
                AsyncWebParameter* p = request->getParam(i);
                if(p->isPost()) {
                    if (p->name() == "ssid") {
                        String str = p->value();
                        Serial.printf("SSID set to: %s\r\n", str.c_str());
                        writeFile(SPIFFS, ssidPath, str.c_str());
                    } else if (p->name() == "pass") {
                        String str = p->value();
                        Serial.printf("Password set to: %s\r\n", str.c_str());
                        writeFile(SPIFFS, passPath, str.c_str());
                    }
                }
            }
            request->send(200, "text/plain", "Done. ESP will restart...");
            vTaskDelay(pdMS_TO_TICKS(3000));
            ESP.restart();
        }
    });

    server.on("/aeskey", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (ON_STA_FILTER(request)) {
            request->send(200, "text/html", smartmeter_html);
        }
    });
    server.on("/aeskey", HTTP_POST, [](AsyncWebServerRequest *request) {
        if (ON_STA_FILTER(request)) {
            AsyncWebParameter* p = request->getParam(0);
            if(p->isPost()) {
                Serial.printf("POST[%s]: %s\n", p->name().c_str(), p->value().c_str());
                if (p->name() == "aes-key") {
                    String str = p->value();
                    Serial.printf("AES-Key set to: %s\r\n", str.c_str());
                    // Write file to save value
                    writeFile(SPIFFS, aeskeyPath, str.c_str());
                }
            }
            request->send(200, "text/plain", "Done. ESP will restart...");
            vTaskDelay(pdMS_TO_TICKS(3000));
            ESP.restart();
        }
    });

    server.on("/mqtt", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (ON_STA_FILTER(request)) {
            request->send(200, "text/html", mqtt_html);
        }
    });
    server.on("/mqtt", HTTP_POST, [](AsyncWebServerRequest *request) {
        if (ON_STA_FILTER(request)) {
            int params = request->params();
            for (int i = 0; i < params; i++) {
                AsyncWebParameter* p = request->getParam(i);
                if (p->isPost()) {
                    Serial.printf("POST[%s]: %s\n", p->name().c_str(), p->value().c_str());
                    if (p->name() == "mqtt-broker") {
                        String str = p->value();
                        Serial.printf("mqtt broker set to: %s\r\n", str.c_str());
                        // Write file to save value
                        writeFile(SPIFFS, mqttbrokerPath, str.c_str());
                    } else if (p->name() == "mqtt-port") {
                        String str = p->value();
                        Serial.printf("mqtt broker port set to: %s\r\n", str.c_str());
                        // Write file to save value
                        writeFile(SPIFFS, mqttportPath, str.c_str());
                    } else if (p->name() == "mqtt-topic") {
                        String str = p->value();
                        Serial.printf("mqtt topic set to: %s\r\n", str.c_str());
                        // Write file to save value
                        writeFile(SPIFFS, mqtttopicPath, str.c_str());
                    }
                }
            }
            request->send(200, "text/plain", "Done. ESP will restart...");
            vTaskDelay(pdMS_TO_TICKS(3000));
            ESP.restart();
        }
    });
    server.on("/wlan", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (ON_STA_FILTER(request)) {
            request->send(200, "text/html", wlan_html);
        }
    });
    server.on("/wlan", HTTP_POST, [](AsyncWebServerRequest *request) {
        if (ON_STA_FILTER(request)) {
            int params = request->params();
            for (int i = 0; i < params; i++) {
                AsyncWebParameter* p = request->getParam(i);
                if(p->isPost()) {
                    if (p->name() == "ssid") {
                        String str = p->value();
                        Serial.printf("SSID set to: %s\r\n", str.c_str());
                        writeFile(SPIFFS, ssidPath, str.c_str());
                    } else if (p->name() == "pass") {
                        String str = p->value();
                        Serial.printf("Password set to: %s\r\n", str.c_str());
                        writeFile(SPIFFS, passPath, str.c_str());
                    }
                }
            }
            request->send(200, "text/plain", "Done. ESP will restart...");
            vTaskDelay(pdMS_TO_TICKS(3000));
            ESP.restart();
        }
    });
    server.on("/info", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (ON_STA_FILTER(request)) {
            String info;
            char buf[3];
            int64_t ts = esp_timer_get_time() / 1000000;
            uint32_t seconds = ts % 60;
            uint32_t minutes = ts / 60 % 60;
            uint32_t hours = ts / (60 * 60) % 24;
            uint32_t days = ts / (60 * 60 * 24);
            info = "Uptime\r\n    Days ";
            info += days;
            info += " ";
            snprintf(buf, sizeof(buf), "%02u", hours);
            info += buf;
            info += ":";
            snprintf(buf, sizeof(buf), "%02u", minutes);
            info += buf;
            info += ":";
            snprintf(buf, sizeof(buf), "%02u", seconds);
            info += buf;
            info += "\r\n\r\n";
            info += "Wifi\r\n    SSID: ";
            info += WiFi.SSID();
            info += "\r\n    RSSI: ";
            info += WiFi.RSSI();
            info += " dBm\r\n    channel: ";
            info += WiFi.channel();
            info += "\r\n";
            request->send(200, "text/plain", info);
        }
    });
}

static void SetupHtml(void) {

    wlan_html = readFile(SPIFFS, "/wifimanager.html");
    if (!ssid.isEmpty()) {
        String str("value=\"");
        str.concat(ssid);
        str.concat("\"");
        wlan_html.replace("value=\"ssid\"", str);
    }
    if (!pass.isEmpty()) {
        String str("value=\"");
        str.concat(pass);
        str.concat("\"");
        wlan_html.replace("value=\"pass\"", str);
    }
    smartmeter_html = readFile(SPIFFS, "/smartmeter.html");
    if (!aeskey.isEmpty()) {
        String str("value=\"");
        str.concat(aeskey);
        str.concat("\"");
        smartmeter_html.replace("value=\"00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff\"", str);
    }

    mqtt_html = readFile(SPIFFS, "/mqtt.html");
    if (!mqttbroker.isEmpty()) {
        String str("value=\"");
        str.concat(mqttbroker);
        str.concat("\"");
        mqtt_html.replace("value=\"broker\"", str);
    }
    if (mqttport != 0) {
        String str("value=\"");
        str.concat(mqttport);
        str.concat("\"");
        mqtt_html.replace("value=\"port\"", str);
    }
    if (!mqtttopic.isEmpty()) {
        String str("value=\"");
        str.concat(mqtttopic);
        str.concat("\"");
        mqtt_html.replace("value=\"topic\"", str);
    }
}

void setup() {
    pinMode(ledPin, OUTPUT);
    digitalWrite(ledPin, HIGH);
    ledState = 1;

    Serial.begin(115200);

    if (!SPIFFS.begin(true)) {
       Serial.println("SPIFFS error");
    }

    // Load values saved in SPIFFS
    ssid = readFile(SPIFFS, ssidPath);
    pass = readFile(SPIFFS, passPath);
    aeskey = readFile(SPIFFS, aeskeyPath);
    mqttbroker = readFile(SPIFFS, mqttbrokerPath);
    String port = readFile(SPIFFS, mqttportPath);
    if (port) {
        mqttport = strtol(port.c_str(), 0, 10);
    }
    mqtttopic = readFile(SPIFFS, mqtttopicPath);

    Serial.printf("\r\nConfiguration:\r\n");
    Serial.printf("ssid: %s\r\n", ssid.c_str());
    Serial.printf("pass: %s\r\n", pass.c_str());
    Serial.printf("aeskey: %s\r\n", aeskey.c_str());
    Serial.printf("mqttbroker: %s\r\n", mqttbroker.c_str());
    Serial.printf("mqttport: %d\r\n", mqttport);
    Serial.printf("mqtttopic: %s\r\n\r\n", mqtttopic.c_str());

    Set_key(aeskey);

    InitWiFi();

    SetupHtml();
    RouteWebpages();

    server.serveStatic("/", SPIFFS, "/");

    if (mqttbroker && mqttport && mqtttopic) {
        mqttClient.onConnect(OnMqttConnect);
        mqttClient.onDisconnect(OnMqttDisconnect);
        mqttClient.setServer(mqttbroker.c_str(), mqttport);
        ConnectToMqtt();
    }
    initWebSocket();
    AsyncElegantOTA.begin(&server);
    server.begin();

    digitalWrite(ledPin, LOW);
    ledState = 0;

    UsbInit(UsbRx, &usbTx, UsbNewDev);
}

void loop() {

    uint32_t currentMillis = millis();
    static bool ap = true;
    static bool printip = true;

    if (reconnectMqtt && ((currentMillis - lastReconnectMqttMs) > 5000)) {
        ConnectToMqtt();
    }

    ws.cleanupClients();

    if ((WiFi.status() != WL_CONNECTED) && ((currentMillis - lastReconnectWifiMs) >= 30000)) {
        Serial.println("Reconnecting to WiFi...");
        WiFi.reconnect();
        lastReconnectWifiMs = currentMillis;
        printip = true;
    }

    if ((WiFi.status() == WL_CONNECTED) && printip) {
        Serial.print("IP address: ");
        Serial.println(WiFi.localIP());
        printip = false;
    }

    if (ap && (millis() > (5 * 60 * 1000))) {
        Serial.printf("Stop AP\r\n");
        WiFi.mode(WIFI_STA);
        ap = false;
    }
}
