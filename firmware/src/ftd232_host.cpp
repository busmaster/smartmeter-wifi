#include "esp_system.h"

#include "esp_log.h"
#include "esp_err.h"

#include "HardwareSerial.h"

#include "inttypes.h"
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include "usb/usb_host.h"
#include "usb/ftd232_host.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "esp_check.h"
#include "esp_system.h"

static const char *TAG = "FTD232";

/* FT232 line status */
#define FT_OE      (1<<1)
#define FT_PE      (1<<2)
#define FT_FE      (1<<3)
#define FT_BI      (1<<4)

// spinlock
static portMUX_TYPE ftd232_lock = portMUX_INITIALIZER_UNLOCKED;
#define FTD232_ENTER_CRITICAL()   portENTER_CRITICAL(&ftd232_lock)
#define FTD232_EXIT_CRITICAL()    portEXIT_CRITICAL(&ftd232_lock)

// FTD232 events
#define FTD232_TEARDOWN          BIT0
#define FTD232_TEARDOWN_COMPLETE BIT1

// FTD232 check macros
#define FTD232_CHECK(cond, ret_val) ({                              \
    if (!(cond)) {                                                  \
        return (ret_val);                                           \
    }                                                               \
})

#define FTD232_CHECK_FROM_CRIT(cond, ret_val) ({                    \
    if (!(cond)) {                                                  \
        FTD232_EXIT_CRITICAL();                                     \
        return ret_val;                                             \
    }                                                               \
})

// FTD232 driver object
typedef struct {
    usb_host_client_handle_t ftd232_client_hdl;        /*!< USB Host handle reused for all FTD232 devices in the system */
    SemaphoreHandle_t open_close_mutex;
    EventGroupHandle_t event_group;
    ftd232_new_dev_callback_t new_dev_cb;
    SLIST_HEAD(list_dev, ftd232_dev_s) ftd232_devices_list;   /*!< List of open pseudo devices */
} ftd232_obj_t;

static ftd232_obj_t *p_ftd232_obj = NULL;

/**
 * @brief Default FTD232 driver configuration
 *
 * This configuration is used when user passes NULL to config pointer during device open.
 */
static const ftd232_host_driver_config_t ftd232_driver_config_default = {
    .driver_task_stack_size = 4096,
    .driver_task_priority = 10,
    .xCoreID = 0,
    .new_dev_cb = 0,
};

typedef struct ftd232_dev_s ftd232_dev_t;
struct ftd232_dev_s {
    usb_device_handle_t dev_hdl;          // USB device handle
    void *cb_arg;                         // Common argument for user's callbacks (data IN)
    struct {
        usb_transfer_t *out_xfer;         // OUT data transfer
        usb_transfer_t *in_xfer;          // IN data transfer
        ftd232_data_callback_t in_cb;     // User's callback for async (non-blocking) data IN
        uint16_t in_mps;                  // IN endpoint Maximum Packet Size
        uint8_t *in_data_buffer_base;     // Pointer to IN data buffer in usb_transfer_t
        uint8_t restore_data[2];
        uint8_t *restore_base;
        const usb_intf_desc_t *intf_desc; // Pointer to data interface descriptor
        SemaphoreHandle_t out_mux;        // OUT mutex
    } data;

    struct {
        usb_transfer_t *xfer;             // IN notification transfer
        const usb_intf_desc_t *intf_desc; // Pointer to notification interface descriptor, can be NULL if there is no notification channel in the device
        ftd232_host_dev_callback_t cb;    // User's callback for device events
    } notif;                              // Structure with Notif pipe data

    usb_transfer_t *ctrl_transfer;        // CTRL (endpoint 0) transfer
    SemaphoreHandle_t ctrl_mux;           // CTRL mutex
    ftd232_uart_state_t serial_state;    // Serial State
    int             num_ftd232_intf_desc;    // Number of FTD232 Interface descriptors in following array
    const usb_standard_desc_t **ftd232_intf_desc;   // FTD232 Interface descriptors
    SLIST_ENTRY(ftd232_dev_s) list_entry;
};

/**
 * @brief Data received callback
 *
 * Data (bulk) IN transfer is submitted at the end of this function to ensure continuous poll of IN endpoint.
 *
 * @param[in] transfer Transfer that triggered the callback
 */
static void in_xfer_cb(usb_transfer_t *transfer);

/**
 * @brief Data send callback
 *
 * Reused for bulk OUT and CTRL transfers
 *
 * @param[in] transfer Transfer that triggered the callback
 */
static void out_xfer_cb(usb_transfer_t *transfer);

/**
 * @brief USB Host Client event callback
 *
 * Handling of USB device connection/disconnection to/from root HUB.
 *
 * @param[in] event_msg Event message type
 * @param[in] arg Caller's argument (not used in this driver)
 */
static void usb_event_cb(const usb_host_client_event_msg_t *event_msg, void *arg);

/**
 * @brief Reset IN transfer
 *
 * In in_xfer_cb() we can modify IN transfer parameters, this function resets the transfer to its defaults
 *
 * @param[in] ftd232_dev Pointer to FTD232 device
 */
static void ftd232_reset_in_transfer(ftd232_dev_t *ftd232_dev)
{
    assert(ftd232_dev->data.in_xfer);
    usb_transfer_t *transfer = ftd232_dev->data.in_xfer;
    uint8_t **ptr = (uint8_t **)(&(transfer->data_buffer));
    *ptr = ftd232_dev->data.in_data_buffer_base;
    transfer->num_bytes = transfer->data_buffer_size;
    ftd232_dev->data.restore_base = 0;
}

/**
 * @brief FTD232 driver handling task
 *
 * USB host client registration and deregistration is handled here.
 *
 * @param[in] arg User's argument. Handle of a task that started this task.
 */
static void ftd232_client_task(void *arg)
{
    esp_err_t err;

    ulTaskNotifyTake(pdTRUE, portMAX_DELAY); // Task will be resumed from ftd232_host_install()

    ftd232_obj_t *ftd232_obj = p_ftd232_obj; // Make local copy of the driver's handle
    assert(ftd232_obj->ftd232_client_hdl);

    // Start handling client's events
    while (1) {
        err = usb_host_client_handle_events(ftd232_obj->ftd232_client_hdl, portMAX_DELAY);
        EventBits_t events = xEventGroupGetBits(ftd232_obj->event_group);
        if (events & FTD232_TEARDOWN) {
            break;
        }
    }
    ESP_LOGD(TAG, "Deregistering client");
    ESP_ERROR_CHECK(usb_host_client_deregister(ftd232_obj->ftd232_client_hdl));
    xEventGroupSetBits(ftd232_obj->event_group, FTD232_TEARDOWN_COMPLETE);
    vTaskDelete(NULL);
}

/**
 * @brief Cancel transfer and reset endpoint
 *
 * This function will cancel ongoing transfer a reset its endpoint to ready state.
 *
 * @param[in] dev_hdl USB device handle
 * @param[in] transfer Transfer to be cancelled
 * @return esp_err_t
 */
static esp_err_t ftd232_reset_transfer_endpoint(usb_device_handle_t dev_hdl, usb_transfer_t *transfer)
{
    assert(dev_hdl);
    assert(transfer);

    ESP_RETURN_ON_ERROR(usb_host_endpoint_halt(dev_hdl, transfer->bEndpointAddress), TAG,);
    ESP_RETURN_ON_ERROR(usb_host_endpoint_flush(dev_hdl, transfer->bEndpointAddress), TAG,);
    usb_host_endpoint_clear(dev_hdl, transfer->bEndpointAddress);
    return ESP_OK;
}

/**
 * @brief Start FTD232 device
 *
 * After this call, USB host peripheral will continuously poll IN endpoints.
 *
 * @param ftd232
 * @param[in] in_cb     Data received callback
 * @param[in] user_arg  Optional user's argument, that will be passed to the callbacks
 * @return esp_err_t
 */
static esp_err_t ftd232_start(ftd232_dev_t *ftd232_dev, ftd232_host_dev_callback_t event_cb, ftd232_data_callback_t in_cb, void *user_arg)
{
    esp_err_t ret = ESP_OK;
    assert(ftd232_dev);

    FTD232_ENTER_CRITICAL();
    ftd232_dev->notif.cb = event_cb;
    ftd232_dev->data.in_cb = in_cb;
    ftd232_dev->cb_arg = user_arg;
    FTD232_EXIT_CRITICAL();

    // Claim data interface and start polling its IN endpoint
    ESP_GOTO_ON_ERROR(usb_host_interface_claim(p_ftd232_obj->ftd232_client_hdl, ftd232_dev->dev_hdl, ftd232_dev->data.intf_desc->bInterfaceNumber, 0), err, TAG,);
    if (ftd232_dev->data.in_xfer) {
        ESP_LOGD(TAG, "Submitting poll for BULK IN transfer");
        ESP_ERROR_CHECK(usb_host_transfer_submit(ftd232_dev->data.in_xfer));
    }

    // Everything OK, add the device into list and return
    FTD232_ENTER_CRITICAL();
    SLIST_INSERT_HEAD(&p_ftd232_obj->ftd232_devices_list, ftd232_dev, list_entry);
    FTD232_EXIT_CRITICAL();

    return ret;

err:
    usb_host_interface_release(p_ftd232_obj->ftd232_client_hdl, ftd232_dev->dev_hdl, ftd232_dev->data.intf_desc->bInterfaceNumber);

    return ret;
}

static void ftd232_transfers_free(ftd232_dev_t *ftd232_dev);
/**
 * @brief Helper function that releases resources claimed by FTD232 device
 *
 * Close underlying USB device, free device driver memory
 *
 * @note All interfaces claimed by this device must be release before calling this function
 * @param ftd232_dev FTD232 device handle to be removed
 */
static void ftd232_device_remove(ftd232_dev_t *ftd232_dev)
{
    assert(ftd232_dev);
    ftd232_transfers_free(ftd232_dev);
    free(ftd232_dev->ftd232_intf_desc);
    // We don't check the error code of usb_host_device_close, as the close might fail, if someone else is still using the device (not all interfaces are released)
    usb_host_device_close(p_ftd232_obj->ftd232_client_hdl, ftd232_dev->dev_hdl); // Gracefully continue on error
    free(ftd232_dev);
}

/**
 * @brief Open USB device with requested VID/PID
 *
 * This function has two regular return paths:
 * 1. USB device with matching VID/PID is already opened by this driver: allocate new device on top of the already opened USB device.
 * 2. USB device with matching VID/PID is NOT opened by this driver yet: poll USB connected devices until it is found.
 *
 * @note This function will block for timeout_ms, if the device is not enumerated at the moment of calling this function.
 * @param[in] vid Vendor ID
 * @param[in] pid Product ID
 * @param[in] timeout_ms Connection timeout [ms]
 * @param[out] dev FTD232 device
 * @return esp_err_t
 */
static esp_err_t ftd232_find_and_open_usb_device(uint16_t vid, uint16_t pid, int timeout_ms, ftd232_dev_t **dev)
{
    assert(p_ftd232_obj);
    assert(dev);

    *dev = (ftd232_dev_t *)calloc(1, sizeof(ftd232_dev_t));
    if (*dev == NULL) {
        return ESP_ERR_NO_MEM;
    }

    // First, check list of already opened FTD232 devices
    ESP_LOGD(TAG, "Checking list of opened USB devices");
    ftd232_dev_t *ftd232_dev;
    SLIST_FOREACH(ftd232_dev, &p_ftd232_obj->ftd232_devices_list, list_entry) {
        const usb_device_desc_t *device_desc;
        ESP_ERROR_CHECK(usb_host_get_device_descriptor(ftd232_dev->dev_hdl, &device_desc));
        if (device_desc->idVendor == vid && device_desc->idProduct == pid) {
            // Return path 1:
            (*dev)->dev_hdl = ftd232_dev->dev_hdl;
            return ESP_OK;
        }
    }

    // Second, poll connected devices until new device is connected or timeout
    TickType_t timeout_ticks = (timeout_ms == 0) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    TimeOut_t connection_timeout;
    vTaskSetTimeOutState(&connection_timeout);

    do {
        ESP_LOGD(TAG, "Checking list of connected USB devices");
        uint8_t dev_addr_list[10];
        int num_of_devices;
        ESP_ERROR_CHECK(usb_host_device_addr_list_fill(sizeof(dev_addr_list), dev_addr_list, &num_of_devices));

        // Go through device address list and find the one we are looking for
        for (int i = 0; i < num_of_devices; i++) {
            usb_device_handle_t current_device;
            // Open USB device
            if (usb_host_device_open(p_ftd232_obj->ftd232_client_hdl, dev_addr_list[i], &current_device) != ESP_OK) {
                continue; // In case we failed to open this device, continue with next one in the list
            }
            assert(current_device);
            const usb_device_desc_t *device_desc;
            ESP_ERROR_CHECK(usb_host_get_device_descriptor(current_device, &device_desc));
            if (device_desc->idVendor == vid && device_desc->idProduct == pid) {
                // Return path 2:
                (*dev)->dev_hdl = current_device;
                return ESP_OK;
            }
            usb_host_device_close(p_ftd232_obj->ftd232_client_hdl, current_device);
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    } while (xTaskCheckForTimeOut(&connection_timeout, &timeout_ticks) == pdFALSE);

    // Timeout was reached, clean-up
    free(*dev);
    *dev = NULL;
    return ESP_ERR_NOT_FOUND;
}

esp_err_t ftd232_host_install(const ftd232_host_driver_config_t *driver_config)
{
    // Register USB Host client
    usb_host_client_handle_t usb_client = NULL;
    const usb_host_client_config_t client_config = {
        .is_synchronous = false,
        .max_num_event_msg = 3,
        .async = {
            .client_event_callback = usb_event_cb,
            .callback_arg = NULL
        }
    };

    FTD232_CHECK(!p_ftd232_obj, ESP_ERR_INVALID_STATE);

    // Check driver configuration, use default if NULL is passed
    if (driver_config == NULL) {
        driver_config = &ftd232_driver_config_default;
    }

    // Allocate all we need for this driver
    esp_err_t ret;
    ftd232_obj_t *ftd232_obj = (ftd232_obj_t *)heap_caps_calloc(1, sizeof(ftd232_obj_t), MALLOC_CAP_DEFAULT);
    EventGroupHandle_t event_group = xEventGroupCreate();
    SemaphoreHandle_t mutex = xSemaphoreCreateMutex();
    TaskHandle_t driver_task_h = NULL;
    xTaskCreatePinnedToCore(
        ftd232_client_task, "FTD232", driver_config->driver_task_stack_size, NULL,
        driver_config->driver_task_priority, &driver_task_h, driver_config->xCoreID);

    if (ftd232_obj == NULL || driver_task_h == NULL || event_group == NULL || mutex == NULL) {
        ret = ESP_ERR_NO_MEM;
        goto err;
    }

    ESP_GOTO_ON_ERROR(usb_host_client_register(&client_config, &usb_client), err, TAG, "Failed to register USB host client");

    // Initialize FTD232 driver structure
    SLIST_INIT(&(ftd232_obj->ftd232_devices_list));
    ftd232_obj->event_group = event_group;
    ftd232_obj->open_close_mutex = mutex;
    ftd232_obj->ftd232_client_hdl = usb_client;
    ftd232_obj->new_dev_cb = driver_config->new_dev_cb;

    // Between 1st call of this function and following section, another task might try to install this driver:
    // Make sure that there is only one instance of this driver in the system
    FTD232_ENTER_CRITICAL();
    if (p_ftd232_obj) {
        // Already created
        ret = ESP_ERR_INVALID_STATE;
        FTD232_EXIT_CRITICAL();
        goto client_err;
    } else {
        p_ftd232_obj = ftd232_obj;
    }
    FTD232_EXIT_CRITICAL();

    // Everything OK: Start FTD232 driver task and return
    xTaskNotifyGive(driver_task_h);

    return ESP_OK;

client_err:
    usb_host_client_deregister(usb_client);
err: // Clean-up
    free(ftd232_obj);
    if (event_group) {
        vEventGroupDelete(event_group);
    }
    if (driver_task_h) {
        vTaskDelete(driver_task_h);
    }
    if (mutex) {
        vSemaphoreDelete(mutex);
    }
    return ret;
}

esp_err_t ftd232_host_uninstall()
{
    esp_err_t ret;

    FTD232_ENTER_CRITICAL();
    FTD232_CHECK_FROM_CRIT(p_ftd232_obj, ESP_ERR_INVALID_STATE);
    ftd232_obj_t *ftd232_obj = p_ftd232_obj; // Save Driver's handle to temporary handle
    FTD232_EXIT_CRITICAL();

    xSemaphoreTake(p_ftd232_obj->open_close_mutex, portMAX_DELAY); // Wait for all open/close calls to finish

    FTD232_ENTER_CRITICAL();
    if (SLIST_EMPTY(&p_ftd232_obj->ftd232_devices_list)) { // Check that device list is empty (all devices closed)
        p_ftd232_obj = NULL; // NULL static driver pointer: No open/close calls form this point
    } else {
        ret = ESP_ERR_INVALID_STATE;
        FTD232_EXIT_CRITICAL();
        goto unblock;
    }
    FTD232_EXIT_CRITICAL();

    // Signal to CDC task to stop, unblock it and wait for its deletion
    xEventGroupSetBits(ftd232_obj->event_group, FTD232_TEARDOWN);
    usb_host_client_unblock(ftd232_obj->ftd232_client_hdl);
    ESP_GOTO_ON_FALSE(
        xEventGroupWaitBits(ftd232_obj->event_group, FTD232_TEARDOWN_COMPLETE, pdFALSE, pdFALSE, pdMS_TO_TICKS(100)),
        ESP_ERR_NOT_FINISHED, unblock, TAG,);

    // Free remaining resources and return
    vEventGroupDelete(ftd232_obj->event_group);
    xSemaphoreGive(ftd232_obj->open_close_mutex);
    vSemaphoreDelete(ftd232_obj->open_close_mutex);
    free(ftd232_obj);
    return ESP_OK;

unblock:
    xSemaphoreGive(ftd232_obj->open_close_mutex);
    return ret;
}

esp_err_t ftd232_host_register_new_dev_callback(ftd232_new_dev_callback_t new_dev_cb)
{
    FTD232_ENTER_CRITICAL();
    p_ftd232_obj->new_dev_cb = new_dev_cb;
    FTD232_EXIT_CRITICAL();
    return ESP_OK;
}

/**
 * @brief Free USB transfers used by this device
 *
 * @note There can be no transfers in flight, at the moment of calling this function.
 * @param[in] ftd232_dev Pointer to FTD232 device
 */
static void ftd232_transfers_free(ftd232_dev_t *ftd232_dev)
{
    assert(ftd232_dev);
    if (ftd232_dev->data.in_xfer != NULL) {
        ftd232_reset_in_transfer(ftd232_dev);
        usb_host_transfer_free(ftd232_dev->data.in_xfer);
    }
    if (ftd232_dev->data.out_xfer != NULL) {
        if (ftd232_dev->data.out_xfer->context != NULL) {
            vSemaphoreDelete((SemaphoreHandle_t)ftd232_dev->data.out_xfer->context);
        }
        if (ftd232_dev->data.out_mux != NULL) {
            vSemaphoreDelete(ftd232_dev->data.out_mux);
        }
        usb_host_transfer_free(ftd232_dev->data.out_xfer);
    }
    if (ftd232_dev->ctrl_transfer != NULL) {
        if (ftd232_dev->ctrl_transfer->context != NULL) {
            vSemaphoreDelete((SemaphoreHandle_t)ftd232_dev->ctrl_transfer->context);
        }
        if (ftd232_dev->ctrl_mux != NULL) {
            vSemaphoreDelete(ftd232_dev->ctrl_mux);
        }
        usb_host_transfer_free(ftd232_dev->ctrl_transfer);
    }
}

/**
 * @brief Allocate FTD232 transfers
 *
 * @param[in] ftd232_dev    Pointer to FTD232 device
 * @param[in] in_ep_desc-   Pointer to data IN EP descriptor
 * @param[in] in_buf_len    Length of data IN buffer
 * @param[in] out_ep_desc   Pointer to data OUT EP descriptor
 * @param[in] out_buf_len   Length of data OUT buffer
 * @return esp_err_t
 */
static esp_err_t ftd232_transfers_allocate(ftd232_dev_t *ftd232_dev, const usb_ep_desc_t *in_ep_desc, size_t in_buf_len, const usb_ep_desc_t *out_ep_desc, size_t out_buf_len)
{
    esp_err_t ret;

    // 1. Setup control transfer
    usb_device_info_t dev_info;
    ESP_ERROR_CHECK(usb_host_device_info(ftd232_dev->dev_hdl, &dev_info));
    ESP_GOTO_ON_ERROR(
        usb_host_transfer_alloc(dev_info.bMaxPacketSize0, 0, &ftd232_dev->ctrl_transfer),
        err, TAG,);
    ftd232_dev->ctrl_transfer->timeout_ms = 1000;
    ftd232_dev->ctrl_transfer->bEndpointAddress = 0;
    ftd232_dev->ctrl_transfer->device_handle = ftd232_dev->dev_hdl;
    ftd232_dev->ctrl_transfer->context = ftd232_dev;
    ftd232_dev->ctrl_transfer->callback = out_xfer_cb;
    ftd232_dev->ctrl_transfer->context = xSemaphoreCreateBinary();
    ESP_GOTO_ON_FALSE(ftd232_dev->ctrl_transfer->context, ESP_ERR_NO_MEM, err, TAG,);
    ftd232_dev->ctrl_mux = xSemaphoreCreateMutex();
    ESP_GOTO_ON_FALSE(ftd232_dev->ctrl_mux, ESP_ERR_NO_MEM, err, TAG,);

    // 2. Setup IN data transfer (if it is required (in_buf_len > 0))
    if (in_buf_len != 0) {
        ESP_GOTO_ON_ERROR(
            usb_host_transfer_alloc(in_buf_len, 0, &ftd232_dev->data.in_xfer),
            err, TAG,
        );
        assert(ftd232_dev->data.in_xfer);
        ftd232_dev->data.in_xfer->callback = in_xfer_cb;
        ftd232_dev->data.in_xfer->num_bytes = in_buf_len;
        ftd232_dev->data.in_xfer->bEndpointAddress = in_ep_desc->bEndpointAddress;
        ftd232_dev->data.in_xfer->device_handle = ftd232_dev->dev_hdl;
        ftd232_dev->data.in_xfer->context = ftd232_dev;
        ftd232_dev->data.in_mps = USB_EP_DESC_GET_MPS(in_ep_desc);
        ftd232_dev->data.in_data_buffer_base = ftd232_dev->data.in_xfer->data_buffer;
        ftd232_dev->data.restore_base = 0;
    }

    // 3. Setup OUT bulk transfer (if it is required (out_buf_len > 0))
    if (out_buf_len != 0) {
        ESP_GOTO_ON_ERROR(
            usb_host_transfer_alloc(out_buf_len, 0, &ftd232_dev->data.out_xfer),
            err, TAG,
        );
        assert(ftd232_dev->data.out_xfer);
        ftd232_dev->data.out_xfer->device_handle = ftd232_dev->dev_hdl;
        ftd232_dev->data.out_xfer->context = xSemaphoreCreateBinary();
        ESP_GOTO_ON_FALSE(ftd232_dev->data.out_xfer->context, ESP_ERR_NO_MEM, err, TAG,);
        ftd232_dev->data.out_mux = xSemaphoreCreateMutex();
        ESP_GOTO_ON_FALSE(ftd232_dev->data.out_mux, ESP_ERR_NO_MEM, err, TAG,);
        ftd232_dev->data.out_xfer->bEndpointAddress = out_ep_desc->bEndpointAddress;
        ftd232_dev->data.out_xfer->callback = out_xfer_cb;
    }
    return ESP_OK;

err:
    ftd232_transfers_free(ftd232_dev);
    return ret;
}

/**
 * @brief Find FTD232 interface descriptor and its endpoint descriptors
 *
 * @note This function is called in open procedure of FTD232 compliant devices only.
 * @param[in]  ftd232_dev Pointer to FTD232 device
 * @param[out] in_ep      Pointer to data IN EP descriptor
 * @param[out] out_ep     Pointer to data OUT EP descriptor
 * @return esp_err_t
 */
static esp_err_t ftd232_find_intf_and_ep_desc(ftd232_dev_t *ftd232_dev, const usb_ep_desc_t **in_ep, const usb_ep_desc_t **out_ep)
{
    bool interface_found = false;
    const usb_config_desc_t *config_desc;
    const usb_device_desc_t *device_desc;
    int desc_offset = 0;

    // Get required descriptors
    ESP_ERROR_CHECK(usb_host_get_device_descriptor(ftd232_dev->dev_hdl, &device_desc));
    ESP_ERROR_CHECK(usb_host_get_active_config_descriptor(ftd232_dev->dev_hdl, &config_desc));

    if ((device_desc->idVendor == 0x0403) && (device_desc->bNumConfigurations == 1) && (config_desc->bNumInterfaces == 1)) {
        interface_found = true;
    }

    // Save found interfaces descriptors:
    if (interface_found) {
        // no notification IF and EP
        ftd232_dev->notif.intf_desc = 0;

        // Data IF and EP
        ftd232_dev->data.intf_desc = usb_parse_interface_descriptor(config_desc, 0, 0, &desc_offset);
        assert(ftd232_dev->data.intf_desc);
        int temp_offset = desc_offset;
        for (int i = 0; i < 2; i++) {
            const usb_ep_desc_t *this_ep = usb_parse_endpoint_descriptor_by_index(ftd232_dev->data.intf_desc, i, config_desc->wTotalLength, &desc_offset);
            assert(this_ep);
            if (USB_EP_DESC_GET_EP_DIR(this_ep)) {
                *in_ep = this_ep;
            } else {
                *out_ep = this_ep;
            }
            desc_offset = temp_offset;
        }
        return ESP_OK;
    }
    return ESP_ERR_NOT_FOUND;
}

esp_err_t ftd232_host_open(uint16_t vid, uint16_t pid, const ftd232_host_device_config_t *dev_config, ftd232_dev_hdl_t *ftd232_hdl_ret)
{
    esp_err_t ret;
    const usb_ep_desc_t *in_ep = NULL;
    const usb_ep_desc_t *out_ep = NULL;
    size_t in_buf_size;

    FTD232_CHECK(p_ftd232_obj, ESP_ERR_INVALID_STATE);
    FTD232_CHECK(dev_config, ESP_ERR_INVALID_ARG);
    FTD232_CHECK(ftd232_hdl_ret, ESP_ERR_INVALID_ARG);

    xSemaphoreTake(p_ftd232_obj->open_close_mutex, portMAX_DELAY);
    // Find underlying USB device
    ftd232_dev_t *ftd232_dev;

    ESP_GOTO_ON_ERROR(
        ftd232_find_and_open_usb_device(vid, pid, dev_config->connection_timeout_ms, &ftd232_dev),
        exit, TAG, "USB device with VID: 0x%04X, PID: 0x%04X not found", vid, pid);

    // Find and save relevant interface and endpoint descriptors
    ESP_GOTO_ON_ERROR(
        ftd232_find_intf_and_ep_desc(ftd232_dev, &in_ep, &out_ep),
        err, TAG, "Could not find required interface");

    // Check whether found Interfaces are really FTD232
    assert(ftd232_dev->data.intf_desc->bNumEndpoints == 2);

    // The following line is here for backward compatibility with v1.0.*
    // where fixed size of IN buffer (equal to IN Maximum Packe Size) was used
    in_buf_size = (dev_config->data_cb && (dev_config->in_buffer_size == 0)) ? USB_EP_DESC_GET_MPS(in_ep) : dev_config->in_buffer_size;

    // Allocate USB transfers, claim FTD232 interfaces and return FTD232 handle
    ESP_GOTO_ON_ERROR(ftd232_transfers_allocate(ftd232_dev, in_ep, in_buf_size, out_ep, dev_config->out_buffer_size), err, TAG,);
    ESP_GOTO_ON_ERROR(ftd232_start(ftd232_dev, dev_config->event_cb, dev_config->data_cb, dev_config->user_arg), err, TAG,);
    *ftd232_hdl_ret = (ftd232_dev_hdl_t)ftd232_dev;
    xSemaphoreGive(p_ftd232_obj->open_close_mutex);

    return ESP_OK;

err:
    ftd232_device_remove(ftd232_dev);
exit:
    xSemaphoreGive(p_ftd232_obj->open_close_mutex);
    *ftd232_hdl_ret = NULL;
    return ret;
}

esp_err_t ftd232_host_open_vendor_specific(uint16_t vid, uint16_t pid, const ftd232_host_device_config_t *dev_config, ftd232_dev_hdl_t *ftd232_hdl_ret)
{
    esp_err_t ret;
    // The interface can have 2 data endpoints
    usb_ep_desc_t *in_ep = NULL;
    usb_ep_desc_t *out_ep = NULL;
    const usb_config_desc_t *config_desc;
    int desc_offset;
    int temp_offset;
    usb_ep_desc_t *this_ep;
    size_t in_buf_size;

    FTD232_CHECK(p_ftd232_obj, ESP_ERR_INVALID_STATE);
    FTD232_CHECK(dev_config, ESP_ERR_INVALID_ARG);
    FTD232_CHECK(ftd232_hdl_ret, ESP_ERR_INVALID_ARG);

    xSemaphoreTake(p_ftd232_obj->open_close_mutex, portMAX_DELAY);

    // Find underlying USB device
    ftd232_dev_t *ftd232_dev;
    ret = ftd232_find_and_open_usb_device(vid, pid, dev_config->connection_timeout_ms, &ftd232_dev);
    if (ESP_OK != ret) {
        goto exit;
    }

    // Open procedure for FTD232 non-compliant devices:
    ESP_ERROR_CHECK(usb_host_get_active_config_descriptor(ftd232_dev->dev_hdl, &config_desc));
    ftd232_dev->data.intf_desc = usb_parse_interface_descriptor(config_desc, 0, 0, &desc_offset);
    ESP_GOTO_ON_FALSE(
        ftd232_dev->data.intf_desc,
        ESP_ERR_NOT_FOUND, err, TAG, "Required interface no %d was not found.", 0);
    temp_offset = desc_offset; // Save this offset for later


    // Go through all interface's endpoints and parse Interrupt and Bulk endpoints
    for (int i = 0; i < ftd232_dev->data.intf_desc->bNumEndpoints; i++) {
        this_ep = (usb_ep_desc_t *)usb_parse_endpoint_descriptor_by_index(ftd232_dev->data.intf_desc, i, config_desc->wTotalLength, &desc_offset);
        assert(this_ep);

        if (USB_EP_DESC_GET_XFERTYPE(this_ep) == USB_TRANSFER_TYPE_BULK) {
            if (USB_EP_DESC_GET_EP_DIR(this_ep)) {
                in_ep = this_ep;
            } else {
                out_ep = this_ep;
            }
        }
        desc_offset = temp_offset;
    }

    // The following line is here for backward compatibility with v1.0.*
    // where fixed size of IN buffer (equal to IN Maximum Packet Size) was used
    in_buf_size = (dev_config->data_cb && (dev_config->in_buffer_size == 0)) ? USB_EP_DESC_GET_MPS(in_ep) : dev_config->in_buffer_size;

    // Allocate USB transfers, claim interfaces and return FT232 handle
    ESP_GOTO_ON_ERROR(ftd232_transfers_allocate(ftd232_dev, in_ep, in_buf_size, out_ep, dev_config->out_buffer_size), err, TAG, );
    ESP_GOTO_ON_ERROR(ftd232_start(ftd232_dev, dev_config->event_cb, dev_config->data_cb, dev_config->user_arg), err, TAG,);
    *ftd232_hdl_ret = (ftd232_dev_hdl_t)ftd232_dev;
    xSemaphoreGive(p_ftd232_obj->open_close_mutex);
    return ESP_OK;
err:
    ftd232_device_remove(ftd232_dev);
exit:
    xSemaphoreGive(p_ftd232_obj->open_close_mutex);
    return ret;
}

esp_err_t ftd232_host_close(ftd232_dev_hdl_t ftd232_hdl)
{
    FTD232_CHECK(p_ftd232_obj, ESP_ERR_INVALID_STATE);
    FTD232_CHECK(ftd232_hdl, ESP_ERR_INVALID_ARG);

    xSemaphoreTake(p_ftd232_obj->open_close_mutex, portMAX_DELAY);

    ftd232_dev_t *ftd232_dev = (ftd232_dev_t *)ftd232_hdl;

    // Cancel polling of BULK IN and INTERRUPT IN
    FTD232_ENTER_CRITICAL();
    ftd232_dev->notif.cb = NULL;
    ftd232_dev->data.in_cb = NULL;
    FTD232_EXIT_CRITICAL();
    if (ftd232_dev->data.in_xfer) {
        ESP_ERROR_CHECK(ftd232_reset_transfer_endpoint(ftd232_dev->dev_hdl, ftd232_dev->data.in_xfer));
    }

    // Release all interfaces
    ESP_ERROR_CHECK(usb_host_interface_release(p_ftd232_obj->ftd232_client_hdl, ftd232_dev->dev_hdl, ftd232_dev->data.intf_desc->bInterfaceNumber));

    FTD232_ENTER_CRITICAL();
    SLIST_REMOVE(&p_ftd232_obj->ftd232_devices_list, ftd232_dev, ftd232_dev_s, list_entry);
    FTD232_EXIT_CRITICAL();

    ftd232_device_remove(ftd232_dev);
    xSemaphoreGive(p_ftd232_obj->open_close_mutex);
    return ESP_OK;
}

void ftd232_host_desc_print(ftd232_dev_hdl_t ftd232_hdl)
{
    assert(ftd232_hdl);
    ftd232_dev_t *ftd232_dev = (ftd232_dev_t *)ftd232_hdl;

    const usb_device_desc_t *device_desc;
    const usb_config_desc_t *config_desc;
    ESP_ERROR_CHECK_WITHOUT_ABORT(usb_host_get_device_descriptor(ftd232_dev->dev_hdl, &device_desc));
    ESP_ERROR_CHECK_WITHOUT_ABORT(usb_host_get_active_config_descriptor(ftd232_dev->dev_hdl, &config_desc));
    usb_print_device_descriptor(device_desc);
    usb_print_config_descriptor(config_desc, 0);
}

/**
 * @brief Check finished transfer status
 *
 * Return to on transfer completed OK.
 * Cancel the transfer and issue user's callback in case of an error.
 *
 * @param[in] transfer Transfer to be checked
 * @return true Transfer completed
 * @return false Transfer NOT completed
 */
static bool ftd232_is_transfer_completed(usb_transfer_t *transfer)
{
    ftd232_dev_t *ftd232_dev = (ftd232_dev_t *)transfer->context;
    bool completed = false;

    switch (transfer->status) {
    case USB_TRANSFER_STATUS_COMPLETED:
        completed = true;
        break;
    case USB_TRANSFER_STATUS_NO_DEVICE: // User is notified about device disconnection from usb_event_cb
    case USB_TRANSFER_STATUS_CANCELED:
        break;
    case USB_TRANSFER_STATUS_ERROR:
    case USB_TRANSFER_STATUS_TIMED_OUT:
    case USB_TRANSFER_STATUS_STALL:
    case USB_TRANSFER_STATUS_OVERFLOW:
    case USB_TRANSFER_STATUS_SKIPPED:
    default:
        // Transfer was not completed or cancelled by user. Inform user about this
        if (ftd232_dev->notif.cb) {
            const ftd232_host_dev_event_data_t error_event = {
                .type = FTD232_HOST_ERROR,
                .data = {
                    .error = (int) transfer->status
                }
            };
            ftd232_dev->notif.cb(&error_event, ftd232_dev->cb_arg);
        }
        break;
    }
    return completed;
}

static void in_xfer_cb(usb_transfer_t *transfer)
{
    ftd232_dev_t *ftd232_dev = (ftd232_dev_t *)transfer->context;
    ftd232_host_dev_event_data_t serial_state_event;
    bool processed;
    uint8_t line_stat;
    uint8_t *data_buffer;

    if (!ftd232_is_transfer_completed(transfer)) {
        return;
    }
    if (transfer->actual_num_bytes < 2) {
        ESP_LOGE("FTD232", "in_xfer_cb: num bytes < 2");
    }

    line_stat = transfer->data_buffer[1];
    if (line_stat & (FT_OE | FT_PE | FT_FE | FT_BI)) {
        if (ftd232_dev->notif.cb) {
            serial_state_event.type = FTD232_HOST_SERIAL_LINESTAT;
            serial_state_event.data.serial_state.val = line_stat;
            ftd232_dev->notif.cb(&serial_state_event, ftd232_dev->cb_arg);
        }
        ftd232_reset_in_transfer(ftd232_dev);
    } else if (ftd232_dev->data.in_cb && (transfer->actual_num_bytes > 2)) {
        if (ftd232_dev->data.restore_base) {
            memcpy(ftd232_dev->data.restore_base, ftd232_dev->data.restore_data, sizeof(ftd232_dev->data.restore_data));
        }
        // data_buffer[0] .. modem stat
        // data_buffer[1] .. line stat
        data_buffer = ftd232_dev->data.in_data_buffer_base + 2;
        int num_bytes = transfer->data_buffer + transfer->actual_num_bytes - data_buffer;

        processed = ftd232_dev->data.in_cb(data_buffer, num_bytes, ftd232_dev->cb_arg);

        // Information for developers:
        // In order to save RAM and CPU time, the application can indicate that the received data was not processed and that the application expects more data.
        // In this case, the next received data must be appended to the existing buffer.
        // Since the data_buffer in usb_transfer_t is a constant pointer, we must cast away to const qualifier.
        if (!processed) {
            // In case the received data was not processed, the next RX data must be appended to current buffer
            uint8_t **ptr;
            ptr = (uint8_t **)(&(transfer->data_buffer));
            *ptr += transfer->actual_num_bytes - 2;
            memcpy(ftd232_dev->data.restore_data, *ptr, sizeof(ftd232_dev->data.restore_data));
            ftd232_dev->data.restore_base = *ptr;

            // Calculate remaining space in the buffer. Attention: pointer arithmetics!
            size_t space_left = transfer->data_buffer_size - (transfer->data_buffer - ftd232_dev->data.in_data_buffer_base);
            uint16_t mps = ftd232_dev->data.in_mps;
            transfer->num_bytes = (space_left / mps) * mps; // Round down to MPS for next transfer
            if (transfer->num_bytes == 0) {
                // The IN buffer cannot accept more data, inform the user and reset the buffer
                ESP_LOGW(TAG, "IN buffer overflow");
                ftd232_dev->serial_state.bOverRun = true;
                if (ftd232_dev->notif.cb) {
                    serial_state_event.type = FTD232_HOST_SERIAL_RXBUFFEROVERRUN,
                    ftd232_dev->notif.cb(&serial_state_event, ftd232_dev->cb_arg);
                }
                ftd232_reset_in_transfer(ftd232_dev);
                ftd232_dev->serial_state.bOverRun = false;
            }
        } else {
            ftd232_reset_in_transfer(ftd232_dev);
        }
    }

    ESP_LOGD(TAG, "Submitting poll for BULK IN transfer");
    usb_host_transfer_submit(ftd232_dev->data.in_xfer);
}

static void out_xfer_cb(usb_transfer_t *transfer)
{
    ESP_LOGD(TAG, "out/ctrl xfer cb");
    assert(transfer->context);
    xSemaphoreGive((SemaphoreHandle_t)transfer->context);
}

static void usb_event_cb(const usb_host_client_event_msg_t *event_msg, void *arg)
{
    usb_device_handle_t new_dev;
    ftd232_new_dev_callback_t _new_dev_cb;

    switch (event_msg->event) {
    case USB_HOST_CLIENT_EVENT_NEW_DEV:
        // Guard p_ftd232_obj->new_dev_cb from concurrent access
        ESP_LOGD(TAG, "New device connected");
        FTD232_ENTER_CRITICAL();
        _new_dev_cb = p_ftd232_obj->new_dev_cb;
        FTD232_EXIT_CRITICAL();

        if (_new_dev_cb) {
            if (usb_host_device_open(p_ftd232_obj->ftd232_client_hdl, event_msg->new_dev.address, &new_dev) != ESP_OK) {
                break;
            }
            assert(new_dev);
            _new_dev_cb(new_dev);
            usb_host_device_close(p_ftd232_obj->ftd232_client_hdl, new_dev);
        }

        break;
    case USB_HOST_CLIENT_EVENT_DEV_GONE:
        ESP_LOGD(TAG, "Device suddenly disconnected");
        ftd232_dev_t *ftd232_dev;
        ftd232_dev_t *tftd232_dev;
        // We are using 'SAFE' version of 'SLIST_FOREACH' which enables user to close the disconnected device in the callback
        SLIST_FOREACH_SAFE(ftd232_dev, &p_ftd232_obj->ftd232_devices_list, list_entry, tftd232_dev) {
            if (ftd232_dev->dev_hdl == event_msg->dev_gone.dev_hdl && ftd232_dev->notif.cb) {
                // The suddenly disconnected device was opened by this driver: inform user about this
                const ftd232_host_dev_event_data_t disconn_event = {
                    .type = FTD232_HOST_DEVICE_DISCONNECTED,
                    .data = {
                        .ftd232_hdl = (ftd232_dev_hdl_t)ftd232_dev
                    }
                };
                ftd232_dev->notif.cb(&disconn_event, ftd232_dev->cb_arg);
            }
        }
        break;
    default:
        assert(false);
        break;
    }
}

esp_err_t ftd232_host_data_tx_blocking(ftd232_dev_hdl_t ftd232_dev_hdl, const uint8_t *data, size_t data_len, uint32_t timeout_ms)
{
    esp_err_t ret;
    FTD232_CHECK(ftd232_dev_hdl, ESP_ERR_INVALID_ARG);
    ftd232_dev_t *ftd232_dev = (ftd232_dev_t *)ftd232_dev_hdl;
    FTD232_CHECK(data && (data_len > 0), ESP_ERR_INVALID_ARG);
    FTD232_CHECK(ftd232_dev->data.out_xfer, ESP_ERR_NOT_SUPPORTED); // Device was opened as read-only.
    FTD232_CHECK(data_len <= ftd232_dev->data.out_xfer->data_buffer_size, ESP_ERR_INVALID_SIZE);

    // Take OUT mutex and fill the OUT transfer
    BaseType_t taken = xSemaphoreTake(ftd232_dev->data.out_mux, pdMS_TO_TICKS(timeout_ms));
    if (taken != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    ESP_LOGD(TAG, "Submitting BULK OUT transfer");
    memcpy(ftd232_dev->data.out_xfer->data_buffer, data, data_len);
    ftd232_dev->data.out_xfer->num_bytes = data_len;
    ftd232_dev->data.out_xfer->timeout_ms = timeout_ms;
    ESP_GOTO_ON_ERROR(usb_host_transfer_submit(ftd232_dev->data.out_xfer), unblock, TAG,);

    // Wait for OUT transfer completion
    taken = xSemaphoreTake((SemaphoreHandle_t)ftd232_dev->data.out_xfer->context, pdMS_TO_TICKS(timeout_ms));
    if (!taken) {
        // Reset the endpoint
        ftd232_reset_transfer_endpoint(ftd232_dev->dev_hdl, ftd232_dev->data.out_xfer);
        ret = ESP_ERR_TIMEOUT;
        goto unblock;
    }

    ESP_GOTO_ON_FALSE(ftd232_dev->data.out_xfer->status == USB_TRANSFER_STATUS_COMPLETED, ESP_ERR_INVALID_RESPONSE, unblock, TAG, "Bulk OUT transfer error");
    ESP_GOTO_ON_FALSE(ftd232_dev->data.out_xfer->actual_num_bytes == data_len, ESP_ERR_INVALID_RESPONSE, unblock, TAG, "Incorrect number of bytes transferred");
    ret = ESP_OK;

unblock:
    xSemaphoreGive(ftd232_dev->data.out_mux);
    return ret;
}

esp_err_t ftd232_host_send_control_request(ftd232_dev_hdl_t ftd232_dev_hdl, uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint16_t wLength, uint8_t *data) {

    FTD232_CHECK(ftd232_dev_hdl, ESP_ERR_INVALID_ARG);
    ftd232_dev_t *ftd232_dev = (ftd232_dev_t *)ftd232_dev_hdl;
    esp_err_t ret;
    BaseType_t taken;

    if (wLength > 0) {
        FTD232_CHECK(data, ESP_ERR_INVALID_ARG);
    }
    FTD232_CHECK(ftd232_dev->ctrl_transfer->data_buffer_size >= wLength, ESP_ERR_INVALID_SIZE);

    // Take Mutex and fill the CTRL request
    taken = xSemaphoreTake(ftd232_dev->ctrl_mux, pdMS_TO_TICKS(5000));
    if (!taken) {
        return ESP_ERR_TIMEOUT;
    }
    usb_setup_packet_t *req = (usb_setup_packet_t *)(ftd232_dev->ctrl_transfer->data_buffer);
    uint8_t *start_of_data = (uint8_t *)req + sizeof(usb_setup_packet_t);
    req->bmRequestType = bmRequestType;
    req->bRequest = bRequest;
    req->wValue = wValue;
    req->wIndex = wIndex;
    req->wLength = wLength;

    // For IN transfers we must transfer data ownership to CDC driver
    const bool in_transfer = bmRequestType & USB_BM_REQUEST_TYPE_DIR_IN;
    if (!in_transfer) {
        memcpy(start_of_data, data, wLength);
    }

    ftd232_dev->ctrl_transfer->num_bytes = wLength + sizeof(usb_setup_packet_t);
    ESP_GOTO_ON_ERROR(
        usb_host_transfer_submit_control(p_ftd232_obj->ftd232_client_hdl, ftd232_dev->ctrl_transfer),
        unblock, TAG, "CTRL transfer failed");

    taken = xSemaphoreTake((SemaphoreHandle_t)ftd232_dev->ctrl_transfer->context, pdMS_TO_TICKS(5000));
    if (!taken) {
        // Transfer was not finished, error in USB LIB. Reset the endpoint
        ftd232_reset_transfer_endpoint(ftd232_dev->dev_hdl, ftd232_dev->ctrl_transfer);
        ret = ESP_ERR_TIMEOUT;
        goto unblock;
    }

    ESP_GOTO_ON_FALSE(ftd232_dev->ctrl_transfer->status == USB_TRANSFER_STATUS_COMPLETED, ESP_ERR_INVALID_RESPONSE, unblock, TAG, "Control transfer error");
    ESP_GOTO_ON_FALSE(ftd232_dev->ctrl_transfer->actual_num_bytes == ftd232_dev->ctrl_transfer->num_bytes, ESP_ERR_INVALID_RESPONSE, unblock, TAG, "Incorrect number of bytes transferred");

    // For OUT transfers, we must transfer data ownership to user
    if (in_transfer) {
        memcpy(data, start_of_data, wLength);
    }
    ret = ESP_OK;

unblock:
    xSemaphoreGive(ftd232_dev->ctrl_mux);
    return ret;
}
