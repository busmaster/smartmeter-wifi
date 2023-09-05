#ifndef _USB_H_
#define _USB_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef bool      (*rx_cb)(const uint8_t *, size_t, void *);
typedef esp_err_t (*tx_func)(void *hdl, const uint8_t *, size_t, uint32_t);
typedef void      (*newdev_cb)(void *hdl);

int UsbInit(rx_cb rx, tx_func *tx, newdev_cb newdev);

#ifdef __cplusplus
}
#endif

#endif //_USB_H_