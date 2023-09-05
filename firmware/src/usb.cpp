#include "esp_system.h"
#include "esp_log.h"
#include "esp_err.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "usb/usb_host.h"
#include "usb/ftd232_host.h"
#include "usb/usb.h"

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

static rx_cb     rx_func;
static newdev_cb newdev_func;

static void Comm_init(ftd232_dev_hdl_t ftd232_dev) {

    ftd232_host_send_control_request(ftd232_dev, FT_SIO_SET_BAUDRATE_REQUEST_TYPE, FT_SIO_SET_BAUDRATE_REQUEST, 0x4138, 0, 0, 0);
    ftd232_host_send_control_request(ftd232_dev, FT_SIO_SET_BAUDRATE_REQUEST_TYPE, FT_SIO_SET_DATA_REQUEST,  FT_SIO_SET_DATA_PARITY_EVEN | FT_SIO_SET_DATA_STOP_BITS_1 | 8, 0, 0, 0);
}


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

static void handle_event_ftd232(const ftd232_host_dev_event_data_t *event, void *user_ctx)
{
    switch (event->type) {
        case FTD232_HOST_ERROR:
            ESP_LOGE(TAG, "FTD232 error has occurred, err_no = %d", event->data.error);
            break;
        case FTD232_HOST_DEVICE_DISCONNECTED:
            ESP_LOGD(TAG, "Device suddenly disconnected");
            ESP_ERROR_CHECK(ftd232_host_close(event->data.ftd232_hdl));
            xSemaphoreGive(device_disconnected_sem);
            break;
        case FTD232_HOST_SERIAL_RXBUFFEROVERRUN:
            ESP_LOGE(TAG, "Rx buffer overrun");
            break;
        case FTD232_HOST_SERIAL_LINESTAT:
            ESP_LOGW(TAG, "Line stat %02x", event->data.serial_state.val);
            break;
        default:
            ESP_LOGW(TAG,"Unsupported FTD232: %d", event->type);
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
        .data_cb = rx_func,
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
        if (newdev_func) {
            newdev_func(ftd232_dev);
        }
        Comm_init(ftd232_dev);
        xSemaphoreTake(device_disconnected_sem, portMAX_DELAY);
    }
}

static esp_err_t ftd232_tx(void *arg, const uint8_t *data, size_t data_len, uint32_t timeout_ms) {

    ftd232_dev_hdl_t *dev = (ftd232_dev_hdl_t *)arg;
    return ftd232_host_data_tx_blocking(*dev, data, data_len, timeout_ms);
}

int UsbInit(rx_cb rx, tx_func *tx, newdev_cb newdev) {

    rx_func = rx;
    newdev_func = newdev;
    if (tx) {
        *tx = ftd232_tx;
    }
    xTaskCreate(usb_task, "usb_task", 4096, 0, 2, NULL);
    return 0;
}