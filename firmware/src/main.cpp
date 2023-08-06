#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h>

#include "esp_system.h"
#include "esp_log.h"
#include "esp_err.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <HTTPUpdateServer.h>
#include "usb/usb_host.h"
#include "usb/ftd232_host.h"

#include "aes.h"

WebServer server(80);
HTTPUpdateServer httpUpdater;

const char* ssid = "xxx";
const char* password = "xxx";

#define USB_HOST_PRIORITY   20
#define USB_DEVICE_VID      0x0403
#define USB_DEVICE_PID      0x6001


#define LED_PRIORITY        1

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

static void Led_task(void *arg) {


    while (1) {
        vTaskSuspend(0);
    }
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
static unsigned char key[AES_KEY_LEN] = { 0xbb, 0x35, 0x59, 0x8d, 0x97, 0xc6, 0xa3, 0x1a, 0x29, 0x2b, 0x5c, 0xe8, 0xee, 0xda, 0xe5, 0x7a };
/* lower half of iv is the secondary address - it's the same for all EAG meters */
static unsigned char iv[AES_IV_LEN]  = { 0x2d, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static uint8_t pay_load[MBUS_PAYLOAD_SIZE];


uint32_t pplus;
uint32_t pminus;
uint32_t aplus;
uint32_t aminus;

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
            aplus =  (uint32_t)pay_load[12] | ((uint32_t)pay_load[13] << 8) | ((uint32_t)pay_load[14] << 16) | ((uint32_t)pay_load[15] << 24);
            aminus = (uint32_t)pay_load[19] | ((uint32_t)pay_load[20] << 8) | ((uint32_t)pay_load[21] << 16) | ((uint32_t)pay_load[22] << 24);

            ESP_LOGD(TAG, "P+: %d W\n", pplus);
            ESP_LOGD(TAG, "P-: %d W\n", pminus);
            ESP_LOGD(TAG, "A+: %d Wh\n", aplus);
            ESP_LOGD(TAG, "A-: %d Wh\n", aminus);
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

static void main_task(void *arg) {

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

    task_created = xTaskCreate(Led_task, "led_task", 4096, 0, LED_PRIORITY, 0);

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

void setup() {

    Serial.begin(115200);  

    WiFi.mode(WIFI_STA);
    delay(100);

    WiFi.begin(ssid, password);

    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("");
    Serial.print("IP Addresse: ");
    Serial.println(WiFi.localIP());

  server.on("/", [](){
    String msg = "<H1>smif</H1>\n";
    msg += "uptime " + String(millis() / 1000) + "s<br />\n";
    msg += "<H2>Befehle</H2>\n<p>";
    msg += "<a href=\"update\">Update</a><br />\n";
    msg += "</p>\n";
    msg += "<H2>WiFi</H2>\n<p>";
    msg += "IP: " + WiFi.localIP().toString() + "<br />\n";
    msg += "Mask: " + WiFi.subnetMask().toString() + "<br />\n";
    msg += "GW: " + WiFi.gatewayIP().toString() + "<br />\n";
    msg += "MAC: " + WiFi.macAddress() + "<br />\n";
    msg += "SSID: " + String(WiFi.SSID()) + "<br />\n";
    msg += "RSSI: " + String(WiFi.RSSI()) + "<br />\n";
    msg += "<H2>Meter</H2>\n<p>";
    msg += "P+: " + String(pplus) + " W<br />\n";
    msg += "P-: " + String(pminus) + " W<br />\n";
    msg += "A+: " + String(aplus) + " Wh<br />\n";
    msg += "A-: " + String(aminus) + " Wh<br />\n";
    msg += "</p>\n";
    server.send(200, "text/html", msg);
    server.send(302, "text/plain", "");
  });

    httpUpdater.setup(&server);

    server.begin();
    Serial.println("HTTP Server gestartet");

    pinMode(37, OUTPUT);
    digitalWrite(37, HIGH);

    
    xTaskCreate(main_task, "main_task", 4096, 0, 2, NULL);
}

void loop() {

    server.handleClient();
}
