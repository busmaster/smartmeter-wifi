/*
 * SPDX-FileCopyrightText: 2015-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include "usb/usb_host.h"
//#include "usb_types_ftd232.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ftd232_dev_s *ftd232_dev_hdl_t;

/**
 * @brief Line Coding structure
 * @see Table 17, USB CDC-PSTN specification rev. 1.2
 */
typedef struct {
    uint32_t dwDTERate;  // in bits per second
    uint8_t bCharFormat; // 0: 1 stopbit, 1: 1.5 stopbits, 2: 2 stopbits
    uint8_t bParityType; // 0: None, 1: Odd, 2: Even, 3: Mark, 4: Space
    uint8_t bDataBits;   // 5, 6, 7, 8 or 16
} __attribute__((packed)) ftd232_line_coding_t;

/**
 * @brief UART State Bitmap
 * @see Table 31, USB CDC-PSTN specification rev. 1.2
 */
typedef union {
    struct {
        uint16_t bRxCarrier : 1;  // State of receiver carrier detection mechanism of device. This signal corresponds to V.24 signal 109 and RS-232 signal DCD.
        uint16_t bTxCarrier : 1;  // State of transmission carrier. This signal corresponds to V.24 signal 106 and RS-232 signal DSR.
        uint16_t bBreak : 1;      // State of break detection mechanism of the device.
        uint16_t bRingSignal : 1; // State of ring signal detection of the device.
        uint16_t bFraming : 1;    // A framing error has occurred.
        uint16_t bParity : 1;     // A parity error has occurred.
        uint16_t bOverRun : 1;    // Received data has been discarded due to overrun in the device.
        uint16_t reserved : 9;
    };
    uint16_t val;
} ftd232_uart_state_t;

/**
 * @brief CDC-ACM Device Event types to upper layer
 *
 */
typedef enum {
    FTD232_HOST_ERROR,
    FTD232_HOST_SERIAL_RXBUFFEROVERRUN,
    FTD232_HOST_SERIAL_LINESTAT,
    FTD232_HOST_DEVICE_DISCONNECTED
} ftd232_host_dev_event_t;

/**
 * @brief CDC-ACM Device Event data structure
 *
 */
typedef struct {
    ftd232_host_dev_event_t type;
    union {
        int error;                         //!< Error code from USB Host
        ftd232_uart_state_t serial_state; //!< Serial (UART) state
        bool network_connected;            //!< Network connection event
        ftd232_dev_hdl_t ftd232_hdl;         //!< Disconnection event
    } data;
} ftd232_host_dev_event_data_t;

/**
 * @brief New USB device callback
 *
 * Provides already opened usb_dev, that will be closed after this callback returns.
 * This is useful for peeking device's descriptors, e.g. peeking VID/PID and loading proper driver.
 *
 * @attention This callback is called from USB Host context, so the CDC device can't be opened here.
 */
typedef void (*ftd232_new_dev_callback_t)(usb_device_handle_t usb_dev);

/**
 * @brief Data receive callback type
 *
 * @param[in] data     Pointer to received data
 * @param[in] data_len Lenght of received data in bytes
 * @param[in] user_arg User's argument passed to open function
 * @return true        Received data was processed     -> Flush RX buffer
 * @return false       Received data was NOT processed -> Append new data to the buffer
 */
typedef bool (*ftd232_data_callback_t)(const uint8_t *data, size_t data_len, void *user_arg);

/**
 * @brief Device event callback type
 *
 * @param[in] event    Event strucutre
 * @param[in] user_arg User's argument passed to open function
 */
typedef void (*ftd232_host_dev_callback_t)(const ftd232_host_dev_event_data_t *event, void *user_ctx);

/**
 * @brief Configuration structure of USB Host CDC-ACM driver
 *
 */
typedef struct {
    size_t driver_task_stack_size;         /**< Stack size of the driver's task */
    unsigned driver_task_priority;         /**< Priority of the driver's task */
    int  xCoreID;                          /**< Core affinity of the driver's task */
    ftd232_new_dev_callback_t new_dev_cb; /**< New USB device connected callback. Can be NULL. */
} ftd232_host_driver_config_t;

/**
 * @brief Configuration structure of FTD232 device
 *
 */
typedef struct {
    uint32_t connection_timeout_ms;       /**< Timeout for USB device connection in [ms] */
    size_t out_buffer_size;               /**< Maximum size of USB bulk out transfer, set to 0 for read-only devices */
    size_t in_buffer_size;                /**< Maximum size of USB bulk in transfer */
    ftd232_host_dev_callback_t event_cb; /**< Device's event callback function. Can be NULL */
    ftd232_data_callback_t data_cb;      /**< Device's data RX callback function. Can be NULL for write-only devices */
    void *user_arg;                       /**< User's argument that will be passed to the callbacks */
} ftd232_host_device_config_t;

/**
 * @brief Install CDC-ACM driver
 *
 * - USB Host Library must already be installed before calling this function (via usb_host_install())
 * - This function should be called before calling any other CDC driver functions
 *
 * @param[in] driver_config Driver configuration structure. If set to NULL, a default configuration will be used.
 * @return esp_err_t
 */
esp_err_t ftd232_host_install(const ftd232_host_driver_config_t *driver_config);

/**
 * @brief Uninstall CDC-ACM driver
 *
 * - Users must ensure that all CDC devices must be closed via cdc_acm_host_close() before calling this function
 *
 * @return esp_err_t
 */
esp_err_t ftd232_host_uninstall(void);

/**
 * @brief Register new USB device callback
 *
 * The callback will be called for every new USB device, not just CDC-ACM class.
 *
 * @param[in] new_dev_cb New device callback function
 * @return esp_err_t
 */
esp_err_t ftd232_host_register_new_dev_callback(ftd232_new_dev_callback_t new_dev_cb);

/**
 * @brief Open CDC-ACM compliant device
 *
 * CDC-ACM compliant device must contain either an Interface Association Descriptor or CDC-Union descriptor,
 * which are used for the driver's configuration.
 *
 * @param[in] vid           Device's Vendor ID
 * @param[in] pid           Device's Product ID
 * @param[in] interface_idx Index of device's interface used for CDC-ACM communication
 * @param[in] dev_config    Configuration structure of the device
 * @param[out] ftd232_hdl_ret  CDC device handle
 * @return esp_err_t
 */
esp_err_t ftd232_host_open(uint16_t vid, uint16_t pid, const ftd232_host_device_config_t *dev_config, ftd232_dev_hdl_t *ftd232_hdl_ret);

/**
 * @brief Open CDC-ACM non-compliant device
 *
 * CDC-ACM non-compliant device acts as CDC-ACM device but doesn't support all its features.
 * User must provide the interface index that will be used (zero for non-composite devices).
 *
 * @param[in] vid           Device's Vendor ID
 * @param[in] pid           Device's Product ID
 * @param[in] interface_idx Index of device's interface used for CDC-ACM like communication
 * @param[in] dev_config    Configuration structure of the device
 * @param[out] ftd232_hdl_ret  CDC device handle
 * @return esp_err_t
 */
esp_err_t ftd232_host_open_vendor_specific(uint16_t vid, uint16_t pid, const ftd232_host_device_config_t *dev_config, ftd232_dev_hdl_t *ftd232_hdl_ret);

/**
 * @brief Close CDC device and release its resources
 *
 * @note All in-flight transfers will be prematurely canceled.
 * @param ftd232_hdl CDC handle obtained from cdc_acm_host_open()
 * @return esp_err_t
 */
esp_err_t ftd232_host_close(ftd232_dev_hdl_t ftd232_hdl);

/**
 * @brief Transmit data - blocking mode
 *
 * @param ftd232_hdl CDC handle obtained from cdc_acm_host_open()
 * @param[in] data       Data to be sent
 * @param[in] data_len   Data length
 * @param[in] timeout_ms Timeout in [ms]
 * @return esp_err_t
 */
esp_err_t ftd232_host_data_tx_blocking(ftd232_dev_hdl_t ftd232_hdl, const uint8_t *data, size_t data_len, uint32_t timeout_ms);

/**
 * @brief SetLineCoding function
 *
 * @see Chapter 6.3.10, USB CDC-PSTN specification rev. 1.2
 *
 * @param     ftd232_hdl     CDC handle obtained from cdc_acm_host_open()
 * @param[in] line_coding Line Coding structure
 * @return esp_err_t
 */
esp_err_t ftd232_host_line_coding_set(ftd232_dev_hdl_t ftf232_hdl, const ftd232_line_coding_t *line_coding);

/**
 * @brief GetLineCoding function
 *
 * @see Chapter 6.3.11, USB CDC-PSTN specification rev. 1.2
 *
 * @param      ftd232_hdl     CDC handle obtained from cdc_acm_host_open()
 * @param[out] line_coding Line Coding structure to be filled
 * @return esp_err_t
 */
esp_err_t ftd232_host_line_coding_get(ftd232_dev_hdl_t ftd232_hdl, ftd232_line_coding_t *line_coding);

/**
 * @brief SetControlLineState function
 *
 * @see Chapter 6.3.12, USB CDC-PSTN specification rev. 1.2
 *
 * @param     ftd232_hdl CDC handle obtained from cdc_acm_host_open()
 * @param[in] dtr     Indicates to DCE if DTE is present or not. This signal corresponds to V.24 signal 108/2 and RS-232 signal Data Terminal Ready.
 * @param[in] rts     Carrier control for half duplex modems. This signal corresponds to V.24 signal 105 and RS-232 signal Request To Send.
 * @return esp_err_t
 */
esp_err_t ftd232_host_set_control_line_state(ftd232_dev_hdl_t ftd232_hdl, bool dtr, bool rts);

/**
 * @brief SendBreak function
 *
 * This function will block until the duration_ms has passed.
 *
 * @see Chapter 6.3.13, USB CDC-PSTN specification rev. 1.2
 *
 * @param     ftd232_hdl     CDC handle obtained from cdc_acm_host_open()
 * @param[in] duration_ms Duration of the Break signal in [ms]
 * @return esp_err_t
 */
esp_err_t ftd232_host_send_break(ftd232_dev_hdl_t ftd232_hdl, uint16_t duration_ms);

/**
 * @brief Print device's descriptors
 *
 * Device and full Configuration descriptors are printed in human readable format to stdout.
 *
 * @param ftd232_hdl CDC handle obtained from cdc_acm_host_open()
 */
void ftd232_host_desc_print(ftd232_dev_hdl_t ftd232_hdl);

/**
 * @brief Send command to CTRL endpoint
 *
 * @param        ftd232_hdl       CDC handle obtained from cdc_acm_host_open()
 * @param[in]    bmRequestType Field of USB control request
 * @param[in]    bRequest      Field of USB control request
 * @param[in]    wValue        Field of USB control request
 * @param[in]    wIndex        Field of USB control request
 * @param[in]    wLength       Field of USB control request
 * @param[inout] data          Field of USB control request
 * @return esp_err_t
 */
esp_err_t ftd232_host_send_control_request(ftd232_dev_hdl_t ftd232_hdl, uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint16_t wLength, uint8_t *data);

#ifdef __cplusplus
}
class Ftd232Device {
public:
    // Operators
    Ftd232Device() : ftd232_hdl(NULL) {};
    virtual ~Ftd232Device()
    {
        // Close CDC-ACM device, if it wasn't explicitly closed
        if (this->ftd232_hdl != NULL) {
            this->close();
        }
    }

    inline esp_err_t tx_blocking(uint8_t *data, size_t len, uint32_t timeout_ms = 100)
    {
        return ftd232_host_data_tx_blocking(this->ftd232_hdl, data, len, timeout_ms);
    }

    inline esp_err_t open(uint16_t vid, uint16_t pid, const ftd232_host_device_config_t *dev_config)
    {
        return ftd232_host_open(vid, pid, dev_config, &this->ftd232_hdl);
    }

    inline esp_err_t open_vendor_specific(uint16_t vid, uint16_t pid, const ftd232_host_device_config_t *dev_config)
    {
        return ftd232_host_open_vendor_specific(vid, pid, dev_config, &this->ftd232_hdl);
    }

    inline esp_err_t close()
    {
        const esp_err_t err = ftd232_host_close(this->ftd232_hdl);
        if (err == ESP_OK) {
            this->ftd232_hdl = NULL;
        }
        return err;
    }

    virtual inline esp_err_t line_coding_get(ftd232_line_coding_t *line_coding) const
    {
        return ftd232_host_line_coding_get(this->ftd232_hdl, line_coding);
    }

    virtual inline esp_err_t line_coding_set(ftd232_line_coding_t *line_coding)
    {
        return ftd232_host_line_coding_set(this->ftd232_hdl, line_coding);
    }

    virtual inline esp_err_t set_control_line_state(bool dtr, bool rts)
    {
        return ftd232_host_set_control_line_state(this->ftd232_hdl, dtr, rts);
    }

    virtual inline esp_err_t send_break(uint16_t duration_ms)
    {
        return ftd232_host_send_break(this->ftd232_hdl, duration_ms);
    }

    inline esp_err_t send_control_request(uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint16_t wLength, uint8_t *data)
    {
        return ftd232_host_send_control_request(this->ftd232_hdl, bmRequestType, bRequest, wValue, wIndex, wLength, data);
    }

private:
    Ftd232Device &operator= (const Ftd232Device &Copy);
    bool operator== (const Ftd232Device &param) const;
    bool operator!= (const Ftd232Device &param) const;
    ftd232_dev_hdl_t ftd232_hdl;
};
#endif
