// THIS CODE IS ONLY FOR TESTING, THE DATA ARE RANDOM JUST FOR TESTING THE EXTENDED BT5 Data Size. 

#include <stdio.h>
#include "nvs_flash.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_log.h"  // Ensure this header is included for logging macros


#define LOG_TAG "BT5_EXT_ADV"

// Random Address for Advertising Instances
uint8_t addr_1m[6] = {0xc0, 0xde, 0x52, 0x00, 0x00, 0x01};



esp_ble_gap_ext_adv_params_t ext_adv_params_2M = {
  .type = ESP_BLE_GAP_SET_EXT_ADV_PROP_NONCONN_NONSCANNABLE_UNDIRECTED,
  .interval_min = 0x40,
  .interval_max = 0x40,
  .channel_map = ADV_CHNL_ALL,
  .own_addr_type = BLE_ADDR_TYPE_RANDOM,
  .peer_addr_type = BLE_ADDR_TYPE_RANDOM,
  .peer_addr = {0, 0, 0, 0, 0, 0},
  .filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
  .tx_power = EXT_ADV_TX_PWR_NO_PREFERENCE,
  .primary_phy = ESP_BLE_GAP_PHY_1M,
  .max_skip = 0,
  .secondary_phy = ESP_BLE_GAP_PHY_2M,
  .sid = 1,
  .scan_req_notif = false,
};


/*static uint8_t adv_data_with_wrapper[] = {
    0x02, 0x01, 0x06,
    0x05, 0xFF, 0x12, 0x34, 0x56, 0x78  // Short Manufacturer Data
};*/


static uint8_t adv_data_with_wrapper[] = {
    0x02, 0x01, 0x06,             // Flags
    0xD, 0x09, 'E', 'X', 'T', '_', 'B', 'L', 'E', '_', 'T', 'E', 'S', 'T', // Name
    0x02, 0x0a, 0xeb,
    0x7D, 0XFF, 0x48, 0x03, 0xEA, 0x94, 0x89, 0xB1, 0x76, 0x0B, 0x9E, 0xBB, 0x6A, 0xE0, 0xC0, 0x5C, 0xA2, 0x74, // DET
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
    0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x32, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
    0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
    0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
    0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x67, 0x67, 0x67, 0x67, 0x67
   
};


static uint8_t wrapper[107] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
    0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
    0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
    0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
    0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67
};

// Advertising Data
static uint8_t raw_adv_data_1m[] = {
    0x02, 0x01, 0x06,
    0x11, 0x09, 'E', 'S', 'P', '_', 'B', 'L', 'E', '_', 'T', 'E', 'S', 'T'
};

// GAP Event Handler
static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    switch (event) {
        case ESP_GAP_BLE_EXT_ADV_SET_PARAMS_COMPLETE_EVT:
            ESP_LOGI(LOG_TAG, "Advertising parameters set.");
            esp_ble_gap_ext_adv_set_rand_addr(0, addr_1m);
            break;



            // We can data more than 31 bytes. Wrapper - > 107 - 134 bytes, DRIP Link , 139 byts. 

            

        case ESP_GAP_BLE_EXT_ADV_SET_RAND_ADDR_COMPLETE_EVT:
            ESP_LOGI(LOG_TAG, "Random address set.");
            esp_ble_gap_config_ext_adv_data_raw(0, sizeof(adv_data_with_wrapper), adv_data_with_wrapper);
            break;


        case ESP_GAP_BLE_EXT_ADV_DATA_SET_COMPLETE_EVT:
            ESP_LOGI(LOG_TAG, "Advertising data set. Starting extended advertising...");
            esp_ble_gap_ext_adv_start(1, (esp_ble_gap_ext_adv_t[]){{.instance = 0, .duration = 0}});
            break;

        case ESP_GAP_BLE_EXT_ADV_START_COMPLETE_EVT:
            if (param->ext_adv_start.status == ESP_BT_STATUS_SUCCESS) {
                ESP_LOGI(LOG_TAG, "Extended advertising started successfully.");
            } else {
                ESP_LOGE(LOG_TAG, "Failed to start extended advertising: %d", param->ext_adv_start.status);
            }
            break;

        default:
            ESP_LOGW(LOG_TAG, "Unhandled GAP event: %d", event);
            break;
    }
}

// Main Application Entry Point
void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));
    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());

    ESP_LOGI(LOG_TAG, "Advertising Data Length: %d", sizeof(adv_data_with_wrapper));
for (int i = 0; i < sizeof(adv_data_with_wrapper); i++) {
    ESP_LOGI(LOG_TAG, "Data[%d]: 0x%02X", i, adv_data_with_wrapper[i]);
}

    ESP_ERROR_CHECK(esp_ble_gap_register_callback(gap_event_handler));
    esp_ble_gap_ext_adv_set_params(0, &ext_adv_params_2M);
}
