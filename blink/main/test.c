#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#define TAG "WiFi_Sniffer"

// Callback function to process sniffed packets
void wifi_sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *payload = snifferPacket->payload;

    if (snifferPacket->rx_ctrl.sig_len < 24) return; // Ensure minimum packet size
    
    uint8_t mac_src[6], mac_dest[6];
    
    // Extract source and destination MAC addresses
    for (int i = 0; i < 6; i++) {
        mac_dest[i] = payload[4 + i];
        mac_src[i] = payload[10 + i];
    }

    ESP_LOGI(TAG, "Packet Type: %d, Src MAC: %02X:%02X:%02X:%02X:%02X:%02X, Dest MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             type,
             mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5],
             mac_dest[0], mac_dest[1], mac_dest[2], mac_dest[3], mac_dest[4], mac_dest[5]);
}

// Wi-Fi Event Handler
void wifi_event_handler(void *arg, esp_event_base_t event_base,
                        int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
            case WIFI_EVENT_STA_START:
                ESP_LOGI(TAG, "Wi-Fi started in station mode.");
                break;
            case WIFI_EVENT_STA_DISCONNECTED:
                ESP_LOGI(TAG, "Wi-Fi disconnected, retrying...");
                esp_wifi_connect();
                break;
            default:
                break;
        }
    }
}

// Initialize Wi-Fi in sniffer mode
void wifi_sniffer_init() {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    
    esp_event_loop_create_default();
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL);

    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL};  // Capture all frames
    esp_wifi_set_promiscuous_filter(&filter);

    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_callback);

    ESP_LOGI(TAG, "Wi-Fi sniffer initialized.");
}

void app_main() {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_sniffer_init();
}
