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

#include "usb/usb_host.h"
#include "usb/ftd232_host.h"

#include "aes.h"

AsyncWebServer server(80);

//Variables to save values from HTML form
String aeskey;
String smartmeter_html;
String mqttbroker;
int    mqttport;
String mqtttopic;
String mqtt_html;
String ssid;
String pass;
String wlan_html;

// File paths to save input values permanently
const char* ssidPath = "/ssid.txt";
const char* passPath = "/pass.txt";
const char* aeskeyPath = "/aeskey.txt";
const char* mqttbrokerPath = "/mqttbroker.txt";
const char* mqttportPath = "/mqttport.txt";
const char* mqtttopicPath = "/mqtttopic.txt";

unsigned long previousMillis = 0;
const long interval = 10000;  // interval to wait for Wi-Fi connection (milliseconds)

espMqttClient mqttClient;
bool reconnectMqtt = false;
uint32_t lastReconnect = 0;

// Set LED GPIO
const int ledPin = 37;
// Stores LED state
String ledState;


#define USB_HOST_PRIORITY   20
#define USB_DEVICE_VID      0x0403
#define USB_DEVICE_PID      0x6001

/* FTD232 */
#define FT_SIO_SET_BAUDRATE_REQUEST_TYPE    0x40
#define FT_SIO_SET_BAUDRATE_REQUEST         3

#define FT_SIO_SET_DATA_REQUEST             4
#define FT_SIO_SET_DATA_PARITY_EVEN         (0x2 << 8)
#define FT_SIO_SET_DATA_STOP_BITS_1         (0x0 << 11)

/* line status */
#define FT_OE      (1<<1)
#define FT_PE      (1<<2)
#define FT_FE      (1<<3)
#define FT_BI      (1<<4)

static const char *TAG = "USB-FTD232";
static SemaphoreHandle_t device_disconnected_sem;

static void usb_lib_task(void *arg)
{
    esp_err_t err;
    while (1) {
        // Start handling system events
        uint32_t event_flags;
        err = usb_host_lib_handle_events(portMAX_DELAY, &event_flags);
        if (event_flags & USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS) {
            ESP_ERROR_CHECK(usb_host_device_free_all());
        }
        if (event_flags & USB_HOST_LIB_EVENT_FLAGS_ALL_FREE) {
            // Continue handling USB events to allow device reconnection
        }
    }
}

static bool in_sync;

static void Comm_init(ftd232_dev_hdl_t ftd232_dev) {

    in_sync = false;
    ftd232_host_send_control_request(ftd232_dev, FT_SIO_SET_BAUDRATE_REQUEST_TYPE, FT_SIO_SET_BAUDRATE_REQUEST, 0x4138, 0, 0, 0);
    ftd232_host_send_control_request(ftd232_dev, FT_SIO_SET_BAUDRATE_REQUEST_TYPE, FT_SIO_SET_DATA_REQUEST,  FT_SIO_SET_DATA_PARITY_EVEN | FT_SIO_SET_DATA_STOP_BITS_1 | 8, 0, 0, 0);

}

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

static unsigned char key[AES_KEY_LEN];
/* lower half of iv is the secondary address - it's the same for all EAG meters */
static unsigned char iv[AES_IV_LEN]  = { 0x2d, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static uint8_t pay_load[MBUS_PAYLOAD_SIZE];


uint32_t pplus;
uint32_t pminus;
uint32_t aplus;
uint32_t aminus;
uint32_t qplus;
uint32_t qminus;
uint32_t rplus;
uint32_t rminus;

static bool handle_rx(const uint8_t *data, size_t data_len, void *arg)
{
    static uint8_t search_seq[] = { 0x10, 0x40, 0xf0, 0x30, 0x16 }; /* SND_NKE for 240 */
    static uint8_t counter_seq[] = { 0x68, 0x5f, 0x5f, 0x68, 0x53, 0xf0, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x4, 0x01, 0x0e};
    ftd232_dev_hdl_t *dev = (ftd232_dev_hdl_t *)arg;
    bool send_req = false;
    bool ret = false;
    uint8_t checksum;
    int i;

    if (!in_sync) {
        if (data_len < sizeof(search_seq)) {
            return false;
        } if (data_len > sizeof(search_seq)) {
            return true;
        }
    }

    if ((data_len == sizeof(search_seq)) && (memcmp(search_seq, data, sizeof(search_seq)) == 0)) {
        send_req = true;
        ret = true;
        in_sync = true;
    } else if (data_len == METER_TELEGRAM_SIZE) {
        ret = true;
        send_req = true;
        checksum = 0;
        for (i = MBUS_CHECKSUM_START_OFFS; i <= MBUS_CHECKSUM_END_OFFS; i++) {
            checksum += data[i];
        }
        if (checksum == data[MBUS_CHECKSUM_OFFS]) {
            /* set upper half of iv */
            for (i = 8; i < 16; i++) {
                iv[i] = data[MBUS_ACCESS_NUMBER_OFFS];
            }
            AES128_CBC_decrypt_buffer(pay_load, (uint8_t *)&data[MBUS_PAYLOAD_OFFS], sizeof(pay_load), key, iv);

            pplus =  (uint32_t)pay_load[44] | ((uint32_t)pay_load[45] << 8) | ((uint32_t)pay_load[46] << 16) | ((uint32_t)pay_load[47] << 24);
            pminus = (uint32_t)pay_load[51] | ((uint32_t)pay_load[52] << 8) | ((uint32_t)pay_load[53] << 16) | ((uint32_t)pay_load[54] << 24);
            rplus =  (uint32_t)pay_load[58] | ((uint32_t)pay_load[59] << 8) | ((uint32_t)pay_load[60] << 16) | ((uint32_t)pay_load[61] << 24);
            rminus = (uint32_t)pay_load[66] | ((uint32_t)pay_load[67] << 8) | ((uint32_t)pay_load[68] << 16) | ((uint32_t)pay_load[69] << 24);
            aplus =  (uint32_t)pay_load[12] | ((uint32_t)pay_load[13] << 8) | ((uint32_t)pay_load[14] << 16) | ((uint32_t)pay_load[15] << 24);
            aminus = (uint32_t)pay_load[19] | ((uint32_t)pay_load[20] << 8) | ((uint32_t)pay_load[21] << 16) | ((uint32_t)pay_load[22] << 24);
            qplus =  (uint32_t)pay_load[28] | ((uint32_t)pay_load[29] << 8) | ((uint32_t)pay_load[30] << 16) | ((uint32_t)pay_load[31] << 24);
            qminus = (uint32_t)pay_load[38] | ((uint32_t)pay_load[39] << 8) | ((uint32_t)pay_load[40] << 16) | ((uint32_t)pay_load[41] << 24);

            ESP_LOGD(TAG, "P+: %d W\n", pplus);
            ESP_LOGD(TAG, "P-: %d W\n", pminus);
            ESP_LOGD(TAG, "A+: %d Wh\n", aplus);
            ESP_LOGD(TAG, "A-: %d Wh\n", aminus);
            ESP_LOGD(TAG, "Q+: %d var\n", qplus);
            ESP_LOGD(TAG, "Q-: %d var\n", qminus);
            ESP_LOGD(TAG, "R+: %d varh\n", rplus);
            ESP_LOGD(TAG, "R-: %d varh\n", rminus);

            char message[256];

            snprintf(message, sizeof(message), 
            "{\"counter\":{\"A+\":%d,\"A-\":%d,\"R+\":%d,\"R-\":%d},\"power\":{\"P+\":%d,\"P-\":%d,\"Q+\":%d,\"Q-\":%d}}",
            aplus, aminus, rplus, rminus, pplus, pminus, qplus, qminus);

            if (mqttClient.connected()) {
                mqttClient.publish(mqtttopic.c_str(), 1, false, message);
            }
        } else {
            in_sync = false;
             ESP_LOGE(TAG, "checksum error\n");
        }
    } else if (data_len > METER_TELEGRAM_SIZE) {
        in_sync = false;
        ret = true;
    }

    if (send_req) {
        const uint8_t tx_buf[] = { 0x05, SEARCH_ACK };
        ftd232_host_data_tx_blocking(*dev, tx_buf, sizeof(tx_buf), 100);
    }

    return ret;
}

static void handle_event_ftd232(const ftd232_host_dev_event_data_t *event, void *user_ctx)
{
    switch (event->type) {
        case FTD232_HOST_ERROR:
            ESP_LOGE(TAG, "FTD232 error has occurred, err_no = %d\n", event->data.error);
            break;
        case FTD232_HOST_DEVICE_DISCONNECTED:
            ESP_LOGD(TAG, "Device suddenly disconnected\n");
            ESP_ERROR_CHECK(ftd232_host_close(event->data.ftd232_hdl));
            xSemaphoreGive(device_disconnected_sem);
            break;
        case FTD232_HOST_SERIAL_RXBUFFEROVERRUN:
            ESP_LOGE(TAG, "Rx buffer overrun\n");
            break;
        case FTD232_HOST_SERIAL_LINESTAT:
            ESP_LOGW(TAG, "Line stat %02x\n", event->data.serial_state.val);
            break;
        default:
            ESP_LOGW(TAG,"Unsupported FTD232: %d\n", event->type);
            break;
    }
}

static void usb_task(void *arg) {

    esp_err_t err;
    BaseType_t task_created;
    TaskHandle_t comm_task;
    ftd232_dev_hdl_t ftd232_dev;

    device_disconnected_sem = xSemaphoreCreateBinary();

    const ftd232_host_device_config_t dev_config = {
        .connection_timeout_ms = 1000,
        .out_buffer_size = 512,
        .in_buffer_size = 512,
        .event_cb = handle_event_ftd232,
        .data_cb = handle_rx,
        .user_arg = &ftd232_dev
    };

    usb_host_config_t host_config = {
        .skip_phy_setup = false,
        .intr_flags = ESP_INTR_FLAG_LEVEL1,
    };
    err = usb_host_install(&host_config);

    task_created = xTaskCreate(usb_lib_task, "usb_lib", 4096, 0, USB_HOST_PRIORITY, NULL);
    err = ftd232_host_install(0);

    vTaskDelay(pdMS_TO_TICKS(1000));

    while(1) {
        ftd232_dev = 0;
        err = ftd232_host_open(USB_DEVICE_VID, USB_DEVICE_PID, &dev_config, &ftd232_dev);
        if (ESP_OK != err) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

//      ftd232_host_desc_print(ftd232_dev);

        Comm_init(ftd232_dev);

        xSemaphoreTake(device_disconnected_sem, portMAX_DELAY);
    }
}

// Initialize SPIFFS
void initSPIFFS() {

  if (!SPIFFS.begin(true)) {
    Serial.println("An error has occurred while mounting SPIFFS");
  }
  Serial.println("SPIFFS mounted successfully");
}

// Read File from SPIFFS
String readFile(fs::FS &fs, const char * path) {
  
    Serial.printf("Reading file: %s\r\n", path);

    File file = fs.open(path);
    if (!file || file.isDirectory()) {
        Serial.println("- failed to open file for reading");
        return String();
    }
  
    String fileContent;
    while (file.available()) {
        fileContent = file.readString();
//        fileContent = file.readStringUntil('\n');
        break;     
    }
    file.close();
   
    return fileContent;
}

// Write file to SPIFFS
void writeFile(fs::FS &fs, const char *path, const char *message) {

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


// Initialize WiFi
bool initWiFi() {

    if (ssid == ""){
        Serial.println("Undefined SSID.");
        return false;
    }

    WiFi.mode(WIFI_STA);

    WiFi.begin(ssid.c_str(), pass.c_str());
    Serial.println("Connecting to WiFi...");

    unsigned long currentMillis = millis();
    previousMillis = currentMillis;

    while(WiFi.status() != WL_CONNECTED) {
        currentMillis = millis();
        if (currentMillis - previousMillis >= interval) {
            Serial.println("Failed to connect.");
            return false;
        }
     }

     Serial.println(WiFi.localIP());
     return true;
}

static void Set_key(String aeskey) {

    char str[48];
    int i = 0;
    snprintf(str, sizeof(str), "%s", aeskey.c_str());
    char *tok = strtok(str, " ");
    while ((i < sizeof(key)) && (tok != 0)) {
        key[i] = (uint8_t)strtoul(tok, 0, 16);
        i++;
        tok = strtok(0, " ");
    }
}

void connectToMqtt(void) {
  Serial.println("Connecting to MQTT...");
  if (!mqttClient.connect()) {
    reconnectMqtt = true;
    lastReconnect = millis();
    Serial.println("Connecting failed.");
  } else {
    reconnectMqtt = false;
  }
}

void onMqttConnect(bool sessionPresent) {
  Serial.println("Connected to MQTT.");
  Serial.print("Session present: ");
  Serial.println(sessionPresent);
}

void onMqttDisconnect(espMqttClientTypes::DisconnectReason reason) {
  Serial.printf("Disconnected from MQTT: %u.\n", static_cast<uint8_t>(reason));

  if (WiFi.isConnected()) {
    reconnectMqtt = true;
    lastReconnect = millis();
  }
}

String processor(const String& var){
//  Serial.println(var);
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

void setup() {

    Serial.begin(115200);

    initSPIFFS();
    pinMode(ledPin, OUTPUT);
    digitalWrite(ledPin, LOW);

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

    Serial.println(ssid);
    Serial.println(pass);
    Serial.println(aeskey);
    Serial.println(mqttbroker);
    Serial.println(mqttport);
    Serial.println(mqtttopic);

    Set_key(aeskey);

    if(initWiFi()) {
// https://github.com/bertmelis/espMqttClient/blob/main/examples/simple-esp32/simple-esp32.ino

// https://randomnerdtutorials.com/esp32-dht11-dht22-temperature-humidity-web-server-arduino-ide/

        if (mqttbroker && mqttport && mqtttopic) {
            mqttClient.onConnect(onMqttConnect);
            mqttClient.onDisconnect(onMqttDisconnect);
            mqttClient.setServer(mqttbroker.c_str(), mqttport);
            connectToMqtt();
        }

        // Route for root / web page
        server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
            request->send(SPIFFS, "/index.html", "text/html", false, processor);
        });

        server.serveStatic("/", SPIFFS, "/");

        server.on("/pplus", HTTP_GET, [](AsyncWebServerRequest *request){
            request->send(200, "text/plain", String(pplus));
        });
        server.on("/pminus", HTTP_GET, [](AsyncWebServerRequest *request){
            request->send(200, "text/plain", String(pminus));
        });
        server.on("/qplus", HTTP_GET, [](AsyncWebServerRequest *request){
            request->send(200, "text/plain", String(qplus));
        });
        server.on("/qminus", HTTP_GET, [](AsyncWebServerRequest *request){
            request->send(200, "text/plain", String(qminus));
        });
        server.on("/aplus", HTTP_GET, [](AsyncWebServerRequest *request){
            request->send(200, "text/plain", String(aplus));
        });
        server.on("/aminus", HTTP_GET, [](AsyncWebServerRequest *request){
            request->send(200, "text/plain", String(aminus));
        });
        server.on("/rplus", HTTP_GET, [](AsyncWebServerRequest *request){
            request->send(200, "text/plain", String(rplus));
        });
        server.on("/rminus", HTTP_GET, [](AsyncWebServerRequest *request){
            request->send(200, "text/plain", String(rminus));
        });


        smartmeter_html = readFile(SPIFFS, "/smartmeter.html");
        if (!aeskey.isEmpty()) {
            String str("value=\"");
            str.concat(aeskey);
            str.concat("\"");
            smartmeter_html.replace("value=\"00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff\"", str);
        }
        server.on("/aeskey", HTTP_GET, [](AsyncWebServerRequest *request) {
            request->send(200, "text/html", smartmeter_html);
        });
        server.on("/aeskey", HTTP_POST, [](AsyncWebServerRequest *request) {
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
        });

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
        server.on("/mqtt", HTTP_GET, [](AsyncWebServerRequest *request) {
            request->send(200, "text/html", mqtt_html);
        });
        server.on("/mqtt", HTTP_POST, [](AsyncWebServerRequest *request) {
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
        });
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
        server.on("/wlan", HTTP_GET, [](AsyncWebServerRequest *request) {
            request->send(200, "text/html", wlan_html);
        });        
        server.on("/wlan", HTTP_POST, [](AsyncWebServerRequest *request) {
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
        });

        AsyncElegantOTA.begin(&server);
        server.begin();
    } else {
        // Connect to Wi-Fi network with SSID and password
        Serial.println("Setting AP (Access Point)");
        // NULL sets an open Access Point
        WiFi.softAP("ESP-WIFI-MANAGER", NULL);

        IPAddress IP = WiFi.softAPIP();
        Serial.print("AP IP address: ");
        Serial.println(IP); 

        // Web Server Root URL
        server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
            request->send(SPIFFS, "/wifimanager.html", "text/html");
        });

        server.serveStatic("/", SPIFFS, "/");
    
        server.on("/", HTTP_POST, [](AsyncWebServerRequest *request) {
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
        });
        server.begin();
    }
   
    xTaskCreate(usb_task, "usb_task", 4096, 0, 2, NULL);
}

void loop() {

    static uint32_t currentMillis = millis();

    if (reconnectMqtt && currentMillis - lastReconnect > 5000) {
        connectToMqtt();
    }
}
