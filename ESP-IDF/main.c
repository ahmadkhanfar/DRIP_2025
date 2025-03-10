#include "Arduino.h"
#undef INADDR_NONE  
#include <stdio.h>
#include <inttypes.h>
#include "lwip/sockets.h"  // Ensure lwip includes come first
#include "IPAddress.h"     // Include Arduino header after
#include "mbedtls/ecdsa.h"
#include <AES.h>
#include <Ed25519.h>
#include <SHA256.h>


// using OpenDroneID library
#include <opendroneid.h>

#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_bt_main.h"
#include "esp_http_client.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"  // Ensure this header is included for logging macros
#define LOG_TAG "BT5_EXT_ADV"

#include <string>
#include "esp_gap_ble_api.h"
#include <ArduinoOTA.h>
#include "esp_bt.h"

#include <bitset>
#include <KeccakP-1600-SnP.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <Update.h>

#include <aes.c>
#include "KeccakP-1600-inplace32BI.c"

#include <inttypes.h>  // Include this at the top of the file


unsigned long dripLinkCreationTime;// Global variable to store DRIP Link creation time

unsigned long HDATime;
unsigned long detGenerationTime;    // For DET generation timing
unsigned long wrapperCreationTime;  // For Wrapper creation timing
uint8_t test_message[] = "Test message for signing";
uint8_t test_signature[64];
int hda = 177;
bool linkRec = false;

uint8_t parentDETArray[16];
uint8_t childDETArray[16];

// Wi-Fi Credentials
const char* ssid = "TELUS9379";
const char* password = "FRxkhF5MJn35";
String serverName = "https://vertexpal.com/Drone/";  // Update with your local IP and endpoint

// NTP Server Settings
const char* ntpServer = "pool.ntp.org";
const long gmtOffset_sec = 0;  // Adjust if you need a specific time zone offset
const int daylightOffset_sec = 0;

// Current firmware version
const String currentVersion = "1.3.0";
// Server details
const char* versionUrl = "https://vertexpal.com/Drone/version.txt";
const char* firmwareUrl = "https://vertexpal.com/Drone/firmware/firmware.bin";

uint32_t parentVNB; 

uint32_t parentVNA;

bool deviceConnected = false; 

bool wrapperCreated = false;


 int loops = -1; 

 // Advertising Data
static uint8_t raw_adv_data_1m[] = {
    0x02, 0x01, 0x06,
    0x11, 0x09, 'E', 'S', 'P', '_', 'B', 'L', 'E', '_', 'T', 'E', 'S', 'T'
};

esp_ble_gap_ext_adv_t ext_adv[] = {
    { .instance = 0, .duration = 0, .max_events = 0 }
};


// Defining Parent DET as custom for now 
// DET (16 bytes) stored as a uint8_t array
std:: string childDET; 
std:: string ParentDET;
uint8_t signature[64];
uint8_t parentSignature[64];
std::vector<uint8_t> wrapper;
std::vector<uint8_t> astmPayload;
std::vector<uint8_t> fullPayload;
std::vector<uint8_t> dripLink;
unsigned long lastTransmissionTime = 0;  // To manage timed transmissions
const unsigned long transmissionInterval = 5000;  // 5 seconds
// Function to convert an unsigned int to a binary string with leading zeros
std::string toBinary(unsigned int value, int bits) {
    return std::bitset<64>(value).to_string().substr(64 - bits, bits);  // Convert and trim to required bits
}
// Function to insert a timestamp into a vector (ensuring little-endian format)
void insertUnixTimestamp(std::vector<uint8_t>& vec, uint32_t timestamp) {
   // Serial.printf("Inserting Timestamp: %u (Hex: 0x%08X)\n", timestamp, timestamp);
    for (int i = 0; i < 4; i++) {
        vec.push_back((uint8_t)(timestamp >> (8 * i)));  // Store in little-endian order
    }
}

// Function to get the current timestamp as a Unix epoch time
uint32_t getCurrentUnixTimestamp() {
    struct tm timeInfo;
    time_t now;
    time(&now);
    
    if (getLocalTime(&timeInfo)) {
        Serial.printf("Current Time (UTC): %04d-%02d-%02d %02d:%02d:%02d\n",
                      timeInfo.tm_year + 1900, timeInfo.tm_mon + 1, timeInfo.tm_mday,
                      timeInfo.tm_hour, timeInfo.tm_min, timeInfo.tm_sec);
    } else {
        Serial.println("Failed to get local time, using raw Unix time.");
    }
    
    return static_cast<uint32_t>(now);
}

String byteArrayToHexString(const uint8_t *byteArray, size_t length) {
    String hexString = "";
    for (size_t i = 0; i < length; i++) {
        if (byteArray[i] < 0x10) {
            hexString += "0"; // add leading zero for single digit hex values
        }
        hexString += String(byteArray[i], HEX);
    }
    return hexString;
}


std::string binaryToHex(const std::string& binaryStr) {
    std::string hexStr;
    int len = binaryStr.length();

    // Iterate over every 4 bits and convert them to hex
    for (int i = 0; i < len; i += 4) {
        std::string fourBits = binaryStr.substr(i, 4); // Extract 4 bits
        unsigned int decimalValue = std::stoi(fourBits, nullptr, 2); // Convert binary to decimal

        // Convert decimal to hexadecimal manually
        if (decimalValue < 10) {
            hexStr += '0' + decimalValue; // 0-9
        } else {
            hexStr += 'A' + (decimalValue - 10); // A-F
        }
    }

    return hexStr;
}

// Helper function to convert std::string (hex) to uint8_t array
void hexStringToByteArray(const std::string& hexStr, uint8_t* byteArray, size_t byteArrayLen) {
    for (size_t i = 0; i < byteArrayLen; ++i) {
        std::string byteString = hexStr.substr(2 * i, 2);
        byteArray[i] = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
    }
}

bool isBLEControllerActive() {
    esp_bt_controller_status_t status = esp_bt_controller_get_status();
    return (status == ESP_BT_CONTROLLER_STATUS_ENABLED);
}


void updateAdvDataWithWrapper(const std::vector<uint8_t>& newWrapperData, size_t wrapperSize, bool isLink) {

    fullPayload.clear();
    // Base advertising data (constant part)
    uint8_t baseAdvData[] = {
        //0x02, 0x01, 0x06,
       /* 0x11, 0x07, 
        0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, // UUID (Little-endian)
        0x00, 0x10, 0x00, 0x00, 0xFA, 0xFF, 0x00, 0x00,*/
            // Flags
      //  0x0D, 0x09, 'E', 'X', 'T', '_', 'B', 'L', 'E', '_', 'T', 'E', 'S', 'T', // Name
        //0x02, 0x0a, 0xeb,            // TX Power Level
    };

      // Length and type for service data
    uint8_t serviceDataHeader[] = {
        static_cast<uint8_t>(2 + 1 + newWrapperData.size()), // Length: UUID (16) + Opcode (1) + F3411 Size
        0x16,

        0xFA, 0xFF   // UUID: ASTM Remote ID (0xFFFA)                                               
    };

    // Calculate the dynamic flag based on the wrapper size
    //uint8_t dynamicFlag = static_cast<uint8_t>(wrapperSize & 0xFF) + 3;
    //::astmPayload.clear();

    
     // Calculate total advertising size
    size_t totalSize = sizeof(baseAdvData) + sizeof(serviceDataHeader) + 1 + newWrapperData.size();

    ESP_LOGE(LOG_TAG, "ASTM  data size  %zu bytes", newWrapperData.size());
    wrapperCreated = true;
    // Ensure the size does not exceed BLE advertising limits
    if (totalSize > 255) {
        ESP_LOGE(LOG_TAG, "Advertising data size exceeds BLE limit: %zu bytes", totalSize);
        return;
    }

    // Print wrapper size for debugging
    ESP_LOGI(LOG_TAG, "Wrapper Size: %zu bytes", wrapperSize);
    static uint8_t messageCounter = 0;
      
    ::fullPayload.reserve(totalSize);

            // Add base advertising data
   // ::fullPayload.insert(::fullPayload.end(), baseAdvData, baseAdvData + sizeof(baseAdvData));
    ::fullPayload.insert(::fullPayload.end(), serviceDataHeader, serviceDataHeader + sizeof(serviceDataHeader));
    fullPayload.push_back(0x0D);
    fullPayload.push_back(messageCounter);  // Counter (1 byte)
    messageCounter = (messageCounter + 1) % 256;  // Increment and wrap at 255
    
    /* if(isLink){
      wrapper.push_back(0x01);
     }else{
        wrapper.push_back(0x02);
     }*/
    // Add the wrapper data
    ::fullPayload.insert(::fullPayload.end(), newWrapperData.begin(), newWrapperData.end());

    if(isBLEControllerActive()){
    esp_err_t err = esp_ble_gap_config_ext_adv_data_raw(0,fullPayload.size(), fullPayload.data());
          ESP_LOGI(LOG_TAG, "Updated Avertise Successed :");
    }



    // Log updated advertising data
    ESP_LOGI(LOG_TAG, "Updated Advertising Data:");
    for (size_t i = 0; i < ::fullPayload.size(); i++) {
        ESP_LOGI(LOG_TAG, "0x%02X", ::fullPayload[i]);
    }

   
}






// Helper function to print a vector of uint8_t as hex values
void printVectorHex(const std::vector<uint8_t>& vec, const char* label) {
    Serial.print(label);
    for (const auto& byte : vec) {
        Serial.printf("%02X ", byte);
    }
    Serial.println();
}

// Key variables for private and public key
// Static Private Key (32 bytes)
uint8_t privateKey[32] = {
    0xe0, 0x26, 0x5f, 0xcc, 0x82, 0x03, 0x71, 0x84,
    0x58, 0x16, 0xa2, 0x61, 0x04, 0x24, 0x60, 0xb3,
    0xf0, 0x1c, 0xd1, 0x7e, 0xf9, 0x0a, 0x58, 0x1c,
    0x6c, 0x53, 0xc9, 0xfa, 0x91, 0xde, 0xae, 0xcd
};
uint8_t publicKey[32];
// BLE Advertising Interval Constants (Bluetooth 5 Optimization)
const uint16_t minInterval = 0x20; // 32 * 0.625ms = 20ms
const uint16_t maxInterval = 0x50; // 80 * 0.625ms = 50ms
//uint8_t contextID[] = { 0x00B5, 0xA69C, 0x795D, 0xF5D5, 0xF008, 0x7F56, 0x843F, 0x2C40 };  // Context ID for DET

uint8_t contextID[] = {
    0x00, 0xB5, 0xA6, 0x9C, 0x79, 0x5D, 0xF5, 0xD5,
    0xF0, 0x08, 0x7F, 0x56, 0x84, 0x3F, 0x2C, 0x40
};
//STRUCTS 
struct ORCHID_HASH {
uint8_t hi[32];  
unsigned long long hashOutput: 64; // 64-bit Hash Output (from cryptographic function)
};
struct DET{
  unsigned int prefix: 28;
  unsigned int raa = 14;
  unsigned int hda = 14;
  unsigned int suiteID: 8;
  ORCHID_HASH hash; 
};

DET det;
// Function to perform the cSHAKE128 hash (Keccak P-1600) for ORCHID
void cshake128(const uint8_t *input, size_t inputLen, const uint8_t *customization, size_t customLen, uint8_t *output, size_t outputLen) {
    KeccakP1600_state keccakState;  // Keccak state structure
    // Initialize the Keccak state
    KeccakP1600_StaticInitialize();
    KeccakP1600_Initialize(&keccakState);
    // Absorb customization string and input data
    KeccakP1600_AddBytes(&keccakState, customization, 0, customLen);
    KeccakP1600_AddBytes(&keccakState, input, 0, inputLen);
    // Apply the permutation
    KeccakP1600_Permute_24rounds(&keccakState);

    // Extract the output (only need 8 bytes for the 64-bit hash)
    KeccakP1600_ExtractBytes(&keccakState, output, 0, outputLen);
}



std:: string det_orchid( unsigned int hda,  unsigned int raa,  unsigned int ipv6, unsigned int suitid, uint8_t publicKey[32], bool isParent){
  std::string b_prefix = toBinary(ipv6, 28);
  std::string b_hid = toBinary(raa, 14) + toBinary(hda, 14);
  std::string b_suitid = toBinary(suitid, 8);
// Concatenate b_prefix, b_hid, and b_ogaid to form the ORCHID left side
  std::string h_orchid_left_bin = b_prefix + b_hid + b_suitid;
  String(toBinary(det.prefix, 28).c_str());
 // Convert the binary string to bytes (as required by cSHAKE)
    std::vector<uint8_t> h_orchid_left;
    for (size_t i = 0; i < h_orchid_left_bin.length(); i += 8) {
        std::bitset<8> byte(h_orchid_left_bin.substr(i, 8));
        h_orchid_left.push_back(byte.to_ulong());
}
 // Append the HI (public key) to the input for the hash
  h_orchid_left.insert(h_orchid_left.end(), publicKey, publicKey + 32); 
  // Perform cSHAKE128 hashing (8-byte hash)
    uint8_t h_hash[8];
    cshake128(h_orchid_left.data(), h_orchid_left.size(), contextID, sizeof(contextID), h_hash, sizeof(h_hash));

    // Convert h_hash to a hexadecimal string
    std::string h_hash_str;
    
    for (int i = 0; i < sizeof(h_hash); i++) {
        char buf[3];
        sprintf(buf, "%02x", h_hash[i]);
        h_hash_str += buf;
    }

     std::string h_orchid_left_hex = binaryToHex(h_orchid_left_bin);

    // Combine the binary ORCHID left side and the hashed right side
    std::string h_orchid = h_orchid_left_hex + h_hash_str;

    // re-convert the h_orchid_left_bin to make sure of the values. 

    // Format the ORCHID into an IPv6 address-like string
    std::string formatted_orchid;
    for (size_t i = 0; i < h_orchid.length(); i += 4) {
        formatted_orchid += h_orchid.substr(i, 4) + ":";
    }
    formatted_orchid.pop_back();  // Remove the trailing ':'

    //String test = binaryToHex(h_orchid);

    Serial.println();
    if(isParent){

    Serial.println("Parent DET ORCHID:" +String(formatted_orchid.c_str()));
     Serial.println("Parent Public Key:");
    }else{
    Serial.println("DET ORCHID:" +String(formatted_orchid.c_str()));
    Serial.println("Child Public Key:");
    }
           for (int i = 0; i < 32; i++) {
        Serial.printf("%02X ", publicKey[i]);
    }
  Serial.println();


    // Serial.println(h_orchid);
    // Serial.println(test);
    return h_orchid;

}





std::vector<uint8_t> createDRIPLink(
    const uint8_t *parentDET, size_t parentDETLen,
    const uint8_t *det, size_t detLen,
    const uint8_t *childPublicKey, size_t publicKeyLen) {

      dripLink.clear();
   
        unsigned long startDRIPLink = millis(); // Start timing
    // Insert timestamps into the DRIP link in little-endian format
    insertUnixTimestamp(dripLink, parentVNB);
    insertUnixTimestamp(dripLink, parentVNA);


    
    // Child DET (Drone's DET)
    dripLink.insert(dripLink.end(), det, det + detLen);

      // Child Public Key
    dripLink.insert(dripLink.end(), childPublicKey, childPublicKey + publicKeyLen);

    // Parent DET
    dripLink.insert(dripLink.end(), parentDET, parentDET + parentDETLen);

    printVectorHex(dripLink, "DRIP LINK BEFORE SIGNING: ");
    // Parent Signature
    dripLink.insert(dripLink.end(), parentSignature, parentSignature + 64);
    unsigned long endDRIPLink = millis(); // End timing
    dripLinkCreationTime = endDRIPLink - startDRIPLink; // Store the result

      

    return dripLink;
}



bool getFromCache(const char* key, uint8_t* buffer, size_t bufferSize) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("cache", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        Serial.printf("Failed to open NVS: %s\n", esp_err_to_name(err));
        return false;
    }

    size_t requiredSize;
    err = nvs_get_blob(handle, key, nullptr, &requiredSize);

    if (err == ESP_OK) {
        if (requiredSize > bufferSize) {
            Serial.printf("Cache size mismatch for key '%s': required %d, buffer %d\n",
                          key, requiredSize, bufferSize);
            nvs_close(handle);
            return false;
        }

        // Dynamically allocate memory for temporary storage
        uint8_t* tempBuffer = (uint8_t*)malloc(requiredSize);
        if (!tempBuffer) {
            Serial.println("Failed to allocate memory for temporary buffer.");
            nvs_close(handle);
            return false;
        }

        err = nvs_get_blob(handle, key, tempBuffer, &requiredSize);
        if (err == ESP_OK) {
            memcpy(buffer, tempBuffer, requiredSize); // Copy data to caller's buffer
            Serial.printf("Successfully retrieved key '%s' from cache.\n", key);
            free(tempBuffer); // Free temporary buffer
            nvs_close(handle);
            return true;
        } else {
            Serial.printf("Error reading blob for key '%s': %s\n", key, esp_err_to_name(err));
        }

        free(tempBuffer);
    } else {
        Serial.printf("Key '%s' not found or size mismatch. Expected: %d\n", key, requiredSize);
    }

    nvs_close(handle);
    return false;
}


bool getUint32FromCache(const char* key, uint32_t* value) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("cache", NVS_READONLY, &handle);
    if (err == ESP_OK) {
        err = nvs_get_u32(handle, key, value);
        if (err == ESP_OK) {
        Serial.printf("Successfully retrieved key '%s' with value %" PRIu32 " from cache.\n", key, *value);

            nvs_close(handle);
            return true;
        } else {
            Serial.printf("Failed to retrieve key '%s': %s\n", key, esp_err_to_name(err));
        }
        nvs_close(handle);
    } else {
        Serial.printf("Failed to open NVS for key '%s': %s\n", key, esp_err_to_name(err));
    }
    return false;
}


bool storeUint32ToCache(const char* key, uint32_t value) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("cache", NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        err = nvs_set_u32(handle, key, value);
        if (err == ESP_OK) {
            Serial.printf("Successfully stored key '%s' with value %" PRIu32 " in cache.\n", key, value);
            nvs_commit(handle);
            nvs_close(handle);
            return true;
        } else {
            Serial.printf("Failed to store key '%s': %s\n", key, esp_err_to_name(err));
        }
        nvs_close(handle);
    } else {
        Serial.printf("Failed to open NVS for key '%s': %s\n", key, esp_err_to_name(err));
    }
    return false;
}






bool storeToCache(const char* key, const uint8_t* data, size_t dataSize) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("cache", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        Serial.printf("Failed to open NVS for writing: %s\n", esp_err_to_name(err));
        return false;
    }

    err = nvs_set_blob(handle, key, data, dataSize);
    if (err == ESP_OK) {
        Serial.printf("Successfully stored key '%s' in cache.\n", key);
        nvs_commit(handle);
        nvs_close(handle);
        return true;
    } else {
        Serial.printf("Failed to store key '%s' in cache: %s\n", key, esp_err_to_name(err));
    }

    nvs_close(handle);
    return false;
}



void sendToServer(bool isParent) {
    String endpoint = "uav_registration.php";
    HTTPClient http;

if (getFromCache("parent_sig", parentSignature, sizeof(parentSignature))) {
    Serial.println("parentSignature retrieved successfully:");
    for (size_t i = 0; i < sizeof(parentSignature); i++) {
        Serial.printf("%02X ", parentSignature[i]);
    }
    Serial.println();
} else {
    Serial.println("Failed to retrieve parentSignature from cache.");
}

if (getFromCache("hda_det", parentDETArray, sizeof(parentDETArray))) {
    Serial.println("parentDETArray retrieved successfully:");
    for (size_t i = 0; i < sizeof(parentDETArray); i++) {
        Serial.printf("%02X ", parentDETArray[i]);
    }
    Serial.println();
} else {
    Serial.println("Failed to retrieve parentDETArray from cache.");
}

if (getUint32FromCache("parent_vna", &parentVNA) && getUint32FromCache("parent_vnb", &parentVNB)) {
  Serial.printf("Parent VNA: %" PRIu32 "\n", parentVNA);
Serial.printf("Parent VNB: %" PRIu32 "\n", parentVNB);
} else {
    Serial.println("Failed to retrieve Parent VNA or VNB from cache.");
}
if (getFromCache("parent_sig", parentSignature, sizeof(parentSignature)) &&
        getFromCache("hda_det", parentDETArray, sizeof(parentDETArray))&& getUint32FromCache("parent_vna", &parentVNA) && getUint32FromCache("parent_vnb", &parentVNB)) {
        
        // Use cached signature and HDA DET
        Serial.println("Using cached signature and HDA DET for DRIP Link creation.");

        // Validate data integrity
    if (parentSignature[0] == 0 || parentDETArray[0] == 0) {
        Serial.println("Error: Cached data appears invalid. Aborting DRIP Link creation.");
        return;
    }
        hexStringToByteArray(childDET.c_str(), childDETArray, sizeof(childDETArray));
        ParentDET = std::string(byteArrayToHexString(parentDETArray, sizeof(parentDETArray)).c_str());


                    
        createDRIPLink(parentDETArray, sizeof(parentDETArray), childDETArray, sizeof(childDETArray), publicKey, sizeof(publicKey));


        

    }else{



      
   

    unsigned long startServer = millis();
    
    // Specify the POST endpoint
    http.begin(serverName + endpoint);
    Serial.println("Connecting to server: " + serverName + endpoint);

    // Set the content type to JSON
    http.addHeader("Content-Type", "application/json");

    // Prepare your JSON data with DET information
    String jsonPayload = "{}";
    if(isParent){
   /* String parentPublicKeyStr = byteArrayToHexString(parentPublicKey, sizeof(parentPublicKey));
    String parentPrivateKeyStr = byteArrayToHexString(parentPrivateKey, sizeof(parentPrivateKey));
    String parentSignatureStr = byteArrayToHexString(parentSignature, sizeof(parentSignature));
    String dripLinkStr = byteArrayToHexString(dripLink.data(), dripLink.size());
    jsonPayload = "{\"ParentDET\": \"" + String(ParentDET.c_str()) + "\", \"pk\": \"" + parentPublicKeyStr + "\",  \"parentSignature\": \"" + parentSignatureStr + "\",  \"dripLink\": \"" + dripLinkStr + "\", \"prK\": \"" + parentPrivateKeyStr + "\"}";*/
    }else{
       String childPrivateKeyStr = byteArrayToHexString(privateKey, sizeof(privateKey));
        String publicKeyStr = byteArrayToHexString(publicKey, sizeof(publicKey));
       String signatureStr = byteArrayToHexString(signature, sizeof(signature));
      String wrapperStr = byteArrayToHexString(wrapper.data(), wrapper.size());
       jsonPayload = "{\"DET\": \"" + String(childDET.c_str()) + "\", \"pk\": \"" + publicKeyStr + "\", \"prK\": \"" + childPrivateKeyStr + "\", \"signature\": \"" + signatureStr + "\", \"hda\": \"" + hda + "\", \"wrapper\": \"" + wrapperStr + "\"}";
       hda ++;

    }

    Serial.println("JSON Payload: " + jsonPayload);  // Debugging: Print payload to verify

    // Send POST request with JSON payload
    int httpResponseCode = http.POST(jsonPayload);

    if (httpResponseCode > 0) {
        String response = http.getString();
        Serial.println("Server Response:");
        Serial.println(response);
         // Parse the response
        DynamicJsonDocument doc(1024);
        DeserializationError error = deserializeJson(doc, response);
        if (error) {
            Serial.print("Failed to parse JSON response: ");
            Serial.println(error.c_str());
        } else {
            // Extract the values
            if (doc[0]["message"] && doc[0]["hda_det"]) {
                 unsigned long endServer = millis();
                  HDATime = endServer - startServer;
                String message = doc[0]["message"].as<String>();
                String hdaDetHex = doc[0]["hda_det"].as<String>();
                String hdaSignatureHex = doc[0]["signature"].as<String>();

                parentVNA = doc[0]["vna"].as<uint32_t>(); // Ensure it's within doc[0]
                parentVNB = doc[0]["vnb"].as<uint32_t>();
                Serial.printf("Parent VNA: %" PRIu32 "\n", parentVNA);
                Serial.printf("Parent VNB: %" PRIu32 "\n", parentVNB);


               if (storeUint32ToCache("parent_vna", parentVNA)) {
                    Serial.println("parentVNA stored successfully.");
                } else {
                    Serial.println("Failed to store parentVNA.");
                }

                if (storeUint32ToCache("parent_vnb", parentVNB)) {
                    Serial.println("parentVNB stored successfully.");
                } else {
                    Serial.println("Failed to store parentVNB.");
                }   
                
                // Update ParentDET
                ParentDET = hdaDetHex.c_str();

                // Debugging outputs
                Serial.println("Message from Server: " + message);
                Serial.println("Received HDA DET: " + String(ParentDET.c_str()));
                Serial.println("Received HDA DET: " + String(ParentDET.c_str()));




                // Convert hdaDetHex to byte array if needed
                hexStringToByteArray(hdaDetHex.c_str(), parentDETArray, sizeof(parentDETArray)); 
                hexStringToByteArray(childDET.c_str(), childDETArray, sizeof(childDETArray));
                hexStringToByteArray(hdaSignatureHex.c_str(), parentSignature, sizeof(parentSignature));
                if (storeToCache("parent_sig", parentSignature, sizeof(parentSignature))) {
                    Serial.println("parentSignature stored successfully.");
                }else {
                    Serial.println("Failed to store parentSignature.");
                }
                  if (storeToCache("hda_det", parentDETArray, sizeof(parentDETArray))) {
                      Serial.println("parentDETArray stored successfully.");
                  } else {
                      Serial.println("Failed to store parentDETArray.");
                  }

                
                
                createDRIPLink(parentDETArray, sizeof(parentDETArray), childDETArray, sizeof(childDETArray), publicKey, sizeof(publicKey));

                linkRec = true;

            } else {
                Serial.println("Invalid JSON response: Missing keys.");
            }


    http.end();  // Close the connection

    }
}
 }

}






void generateKeys(){
  //Ed25519::generatePrivateKey(privateKey);
   Ed25519::derivePublicKey(publicKey, privateKey);
}







void sendWrapperAndPublicKey() {
  // Measure time
    unsigned long startTime = millis();
    String endpoint = "authenticate_det.php";  // Change this to your actual endpoint
    HTTPClient http;

    // Specify the POST endpoint
    http.begin(serverName + endpoint);
    Serial.println("Connecting to server: " + serverName + endpoint);

    // Set the content type to JSON
    http.addHeader("Content-Type", "application/json");

 

    // Convert Wrapper and Public Key to Hex Strings
    String wrapperStr = byteArrayToHexString(wrapper.data(), wrapper.size());
    String publicKeyStr = byteArrayToHexString(publicKey, sizeof(publicKey));

    // Prepare JSON payload
    String jsonPayload = "{\"wrapper\": \"" + wrapperStr + "\", \"pk\": \"" + publicKeyStr + "\"}";
    Serial.println("JSON Payload: " + jsonPayload);  // Debugging: Print payload

    // Send POST request
    int httpResponseCode = http.POST(jsonPayload);
    unsigned long endTime = millis(); 
    if (httpResponseCode > 0) {
        String response = http.getString();
        Serial.println("Server Response:");
        Serial.println(response);

        // Check response for success or failure
        if (response.indexOf("success") >= 0) {
            Serial.println("Wrapper and Public Key verified successfully.");
        } else {
            Serial.println("Verification failed: " + response);
        }
    } else {
        Serial.print("Error on sending POST: ");
        Serial.println(httpResponseCode);
    }

    http.end();  // Close the connection

     // Calculate round-trip time
    unsigned long roundTripTime = endTime - startTime;
    Serial.print("Round-trip time: ");
    Serial.print(roundTripTime);
    Serial.println(" ms");

    delay(10000);
}

std::string vectorToHexString(const std::vector<uint8_t>& vec) {
    String hexString = byteArrayToHexString(vec.data(), vec.size());
    return std::string(hexString.c_str()); // Convert Arduino String to std::string
}



void sendDripLink() {
    // Convert DRIP link to a hex string
    String dripLinkStr = byteArrayToHexString(dripLink.data(), dripLink.size());
    Serial.println("Sending DRIP Link over BLE:");
    Serial.println(dripLinkStr);
}


#include <cmath>
#define EARTH_RADIUS 6371000.0 // Earth's radius in meters

    

     float direction = 90.0;
// Function to generate F3411 data (example values)


#define F3411_MSG_PACK_HEADER 0x0F
#define F3411_BASIC_ID 0x00
#define F3411_LOCATION 0x01
#define F3411_AUTH 0x02
#define F3411_SYSTEM 0x04


/*




Message Counter 
Message Type Version 
Message pack (0xF){
    Message length --> Dynamic basid on what data we have, BASIC ID + Location + Authentication + System 
    Message count --> Constant 0x8
    Basic ID  0x0
    Location 0x1
    Authentication 0x2 
    System 0x4
}







*/

std::vector<uint8_t> createWrapper(const uint8_t *det) {

    unsigned long startWrapper = millis();
    wrapper.clear(); // Clear existing wrapper data
      // Get the current Unix timestamps
    uint32_t validNotBefore = getCurrentUnixTimestamp();  // Now
    
    wrapper.insert(wrapper.end(), (uint8_t*)&validNotBefore, (uint8_t*)&validNotBefore + 4);
    
    uint32_t validNotAfter = validNotBefore + 300;  // Valid for 5 minutes

    wrapper.insert(wrapper.end(), (uint8_t*)&validNotAfter, (uint8_t*)&validNotAfter + 4);

    // Add payload (F3411 messages, 25–100 bytes)
    //wrapper.insert(wrapper.end(), payload.begin(), payload.end());
    // Add DET
    wrapper.insert(wrapper.end(), det, det + 16);

    printVectorHex(wrapper, "WRAPPER BEFORE SIGNING : ");

    // Sign the wrapper
   
    Ed25519::sign(signature, privateKey, publicKey, wrapper.data(), wrapper.size());

// test
    Ed25519::sign(test_signature, privateKey, publicKey, test_message, sizeof(test_message));

    // Add signature to the wrapper
    wrapper.insert(wrapper.end(), signature, signature + 64);
      unsigned long endWrapper = millis();
      wrapperCreationTime = endWrapper - startWrapper;
    

    if(loops == -1){
      sendToServer(true);
      
      sendToServer(false);
      loops++;
    }


  
      
  
      
 


    return wrapper;
}
 std::vector<uint8_t>  defineWrapper (){
        unsigned long startDET = millis();
       childDET =  det_orchid (det.hda, det.raa, det.prefix, det.suiteID, publicKey,false);
        // Convert std::string DETs to uint8_t arrays
        unsigned long endDET = millis();
        detGenerationTime = endDET - startDET;
        uint8_t childDETArray[16];
        hexStringToByteArray(childDET, childDETArray, sizeof(childDETArray));
       //std::vector<uint8_t> payload = createPayload();
         // Create Wrapper
        std::vector<uint8_t> wrapper = createWrapper( childDETArray);
        return wrapper; 
        //
        

}
std::vector<uint8_t> initWrapper(){

    // Setup the constat values. :
    det.prefix = 0x2001003; 
    det.raa = 16376; 
    det.hda = 1025;
    det.suiteID = 5; 
   std::vector<uint8_t> wrapper =  defineWrapper();
   return wrapper;
}

// ASTM F3411 Message Structures
ODID_BasicID_data basicID;
ODID_Location_data location;
ODID_Auth_data auth;
ODID_System_data systemData;
ODID_MessagePack_data messagePack;



std::vector<ODID_Auth_data> constructAuthMessages(const std::vector<uint8_t>& wrapper) {
    size_t totalDataSize = wrapper.size();  // 88 bytes
    size_t firstPageSize = 17;              // First page has 17 bytes
    size_t remainingPageSize = 23;          // Subsequent pages take 23 bytes each

    // Calculate the total number of required pages
    size_t totalPages = 1 + (totalDataSize - firstPageSize + remainingPageSize - 1) / remainingPageSize;

    std::vector<ODID_Auth_data> authMessages(totalPages);

    Serial.printf("Total Auth Pages Before Encoding: %d\n", totalPages); // Debugging

   /* if (totalDataSize != 88) {
        Serial.println("Error: Wrapper size must be exactly 88 bytes.");
        return {};
    }*/

    // --- First Auth Page ---
    memset(&authMessages[0], 0, sizeof(ODID_Auth_data));
    authMessages[0].AuthType = ODID_AUTH_SPECIFIC_AUTHENTICATION;
    authMessages[0].DataPage = 0;
    authMessages[0].LastPageIndex = totalPages - 1;
    authMessages[0].Length = totalDataSize;
    authMessages[0].Timestamp = (uint32_t)time(NULL);

    memcpy(authMessages[0].AuthData, wrapper.data(), firstPageSize);

    // --- Remaining Pages ---
    for (size_t i = 1; i < totalPages; i++) {
        memset(&authMessages[i], 0, sizeof(ODID_Auth_data));
        authMessages[i].AuthType = ODID_AUTH_SPECIFIC_AUTHENTICATION;
        authMessages[i].DataPage = i;
        //authMessages[i].LastPageIndex = totalPages - 1;
        //authMessages[i].Length = totalDataSize;
        //authMessages[i].Timestamp = authMessages[0].Timestamp;

        size_t offset = firstPageSize + (i - 1) * remainingPageSize;
        size_t bytesToCopy = std::min(remainingPageSize, totalDataSize - offset);

        memcpy(authMessages[i].AuthData, wrapper.data() + offset, bytesToCopy);
    }

    return authMessages;
}

/*std::vector<ODID_Auth_data> constructAuthMessages(const std::vector<uint8_t>& wrapper) {
    size_t totalDataSize = wrapper.size();  // 88 bytes
    size_t firstPageSize = 17;              // First page has 17 bytes
    size_t remainingPageSize = 23;          // Subsequent pages take 23 bytes each

    // Calculate the total number of required pages
    size_t totalPages = 1 + (totalDataSize - firstPageSize + remainingPageSize - 1) / remainingPageSize;

    std::vector<ODID_Auth_data> authMessages(totalPages);

    Serial.printf("Total Auth Pages Before Encoding: %d\n", totalPages); // Debugging

    if (totalDataSize != 88) {
        Serial.println("Error: Wrapper size must be exactly 88 bytes.");
        return {};
    }

    // --- First Auth Page ---
    memset(&authMessages[0], 0, sizeof(ODID_Auth_data));
    authMessages[0].AuthType = ODID_AUTH_SPECIFIC_AUTHENTICATION;
    authMessages[0].DataPage = 0;
    authMessages[0].LastPageIndex = totalPages - 1;
    authMessages[0].Length = totalDataSize;
    authMessages[0].Timestamp = (uint32_t)time(NULL);

    memcpy(authMessages[0].AuthData, wrapper.data(), firstPageSize);

    // --- Remaining Pages ---
    for (size_t i = 1; i < totalPages; i++) {
        memset(&authMessages[i], 0, sizeof(ODID_Auth_data));
        authMessages[i].AuthType = ODID_AUTH_SPECIFIC_AUTHENTICATION;
        authMessages[i].DataPage = i;
        authMessages[i].LastPageIndex = totalPages - 1;
        authMessages[i].Length = totalDataSize;
        authMessages[i].Timestamp = authMessages[0].Timestamp;

        size_t offset = firstPageSize + (i - 1) * remainingPageSize;
        size_t bytesToCopy = std::min(remainingPageSize, totalDataSize - offset);

        memcpy(authMessages[i].AuthData, wrapper.data() + offset, bytesToCopy);
    }

    return authMessages;
}*/







    std::vector<uint8_t> constructASTMMessages( bool isWrapper) {
  
    std::vector<uint8_t> wrapper = initWrapper();
    if (wrapper.size() != 88) {
        Serial.println("Error: Wrapper size is not 88 bytes!");
        return {};
    }

    ODID_MessagePack_encoded messagePack;
    memset(&messagePack, 0, sizeof(messagePack));  // Clear structure
    messagePack.ProtoVersion = 2;  // Set Protocol Version 2
    messagePack.MessageType = ODID_MESSAGETYPE_PACKED; // Ensure this is the correct packed message type
  

    if(isWrapper){
    messagePack.MsgPackSize = 8;// Total of 8 messages (Basic ID, Location, Authentication, System)
}else {
    messagePack.MsgPackSize = 8;
}
   messagePack.SingleMessageSize = ODID_MESSAGE_SIZE;  // 25 bytes (0x19 in hex)

    // --- Basic ID Message ---
    ODID_BasicID_data basicID;
    memset(&basicID, 0, sizeof(basicID));
    basicID.IDType = ODID_IDTYPE_SPECIFIC_SESSION_ID;  // Type 4 for Serial Number (DET)
    strcpy(basicID.UASID, childDET.c_str());   // DET as Serial Number

    // --- Location Message ---
    ODID_Location_data location;
    memset(&location, 0, sizeof(location));
    location.Latitude = 42.2917000;  // Example Lat
    location.Longitude = -85.587200; // Example Lon
    location.AltitudeBaro = 100;      // Example Altitude
    location.TimeStamp = (uint32_t)time(NULL);

    //-- Authentication Message (Wrapper split into 5 pages) ---
    std::vector<ODID_Auth_data> authMessages ;
    if(isWrapper == true){
     authMessages = constructAuthMessages(wrapper);
}else {
     authMessages = constructAuthMessages(dripLink);
     ESP_LOGI(LOG_TAG, "Size of drip: %zu bytes\n", dripLink.size());

}
    // --- System Message ---
    ODID_System_data system;
    memset(&system, 0, sizeof(system));
    system.OperatorLocationType = ODID_OPERATOR_LOCATION_TYPE_FIXED;
    system.OperatorLatitude = location.Latitude;
    system.OperatorLongitude = location.Longitude;
    system.Timestamp = (uint32_t)time(NULL);
    

    // --- Encoding the Messages ---
    encodeBasicIDMessage(&messagePack.Messages[0].basicId, &basicID);
    encodeLocationMessage(&messagePack.Messages[1].location, &location);

    // Add the 5/7 authentication messages
    int messages = 0; 
   for (int i = 0; i < authMessages.size(); i++) {
        encodeAuthMessage(&messagePack.Messages[i + 2].auth, &authMessages[i]);
        messages = i;
    }

    encodeSystemMessage(&messagePack.Messages[messages+3].system, &system);

    // Convert to byte array

    ESP_LOGI(LOG_TAG, "Size of ODID_Auth_data: %zu bytes\n", sizeof(messagePack.Messages[0].auth));
    ESP_LOGI(LOG_TAG, "Size of ODID_Auth_data Page 1: %zu bytes\n", sizeof(messagePack.Messages[1].auth));
    ESP_LOGI(LOG_TAG, "Size of ODID_Auth_data Page2 : %zu bytes\n", sizeof(messagePack.Messages[2].auth));
    ESP_LOGI(LOG_TAG, "Size of ODID_Auth_data: Page 3 %zu bytes\n", sizeof(messagePack.Messages[3].auth));
    ESP_LOGI(LOG_TAG, "Size of ODID_Auth_data: Page 4 %zu bytes\n", sizeof(messagePack.Messages[4].auth));
    ESP_LOGI(LOG_TAG, "Size of ODID_Auth_data: Page 5 %zu bytes\n", sizeof(messagePack.Messages[5].auth));
    ESP_LOGI(LOG_TAG, "Size of ODID_Auth_data: Page 6 %zu bytes\n", sizeof(messagePack.Messages[6].auth));
    ESP_LOGI(LOG_TAG, "Size of ODID_Auth_data: Page 7 %zu bytes\n", sizeof(messagePack.Messages[7].auth));

    ESP_LOGI(LOG_TAG, "Size of location: %zu bytes\n", sizeof(messagePack.Messages[0].location));
    ESP_LOGI(LOG_TAG, "Size of system_data: %zu bytes\n", sizeof(messagePack.Messages[0].system));
    ESP_LOGI(LOG_TAG, "Size of basic_data: %zu bytes\n", sizeof(messagePack.Messages[0].basicId));
    ESP_LOGI(LOG_TAG, "Size of ASTM: %zu bytes\n", sizeof(messagePack));
    
    astmPayload.clear();   
    astmPayload.insert(astmPayload.end(), (uint8_t*)&messagePack, (uint8_t*)&messagePack + sizeof(messagePack));
    ESP_LOGI(LOG_TAG, "Size of ASTM: %zu bytes\n", astmPayload.size());

    updateAdvDataWithWrapper(astmPayload, astmPayload.size(), false);
    return astmPayload;
}


/*std::vector<uint8_t> generateF3411Message() {
    std::vector<uint8_t> f3411Message;
    static uint16_t msgCounter = 1;  // 2-byte counter

    // Message Counter (2 bytes, little-endian) --> 1 byte , if it reaches to FF then it would go back to 0. (256). to Keep track of the messages we are receving. 

    f3411Message.push_back(msgCounter & 0xFF);
    f3411Message.push_back((msgCounter >> 8) & 0xFF);
    msgCounter = (msgCounter + 1) % 65536;
     // --- Header Section ---
    // Protocol Version  -- > 
    f3411Message.push_back(0xF2); 
    // --- Message Pack (0x0F) ---
    //f3411Message.push_back(0x0F);  // Message Pack Header
     // Temporary buffer for pack content
    std::vector<uint8_t> packContent;
    uint8_t messageCount = 0; // up to 9. (max is 0)
     // --- Basic ID Message ---
    packContent.push_back(0x02); // Message type protocl version  
    packContent.push_back(0x40); //  ID Type and the UA TYPE
    //packContent.push_back(0x00); 
    const char* serial = "DRONE1234"; // for DET push the byte 0x1 then push byetes of DET then padding with 6 null bytes, first 3 bytes for null padding of the UAS ID FIELD AND LAST 3 bytes for reserved filed basic ID message 
    uint8_t idLength = 1 + strlen(serial);  // ID Type + Serial
    packContent.push_back(idLength);
    packContent.push_back(0x01);  // Serial Number ID Type
    packContent.insert(packContent.end(), serial, serial + strlen(serial));
    messageCount++;

  // --- Location Message ---
    packContent.push_back(0x012);  // Location message type  
    static float latitude = 42.2917000;  // Initial latitude
    static float longitude = -85.587200; // Initial longitude
    static uint16_t altitude = 100;      // Initial altitude
    static uint16_t velocity = 50;       // Velocity
    static float direction = 90.0;       // Direction in degrees
        // Convert velocity to distance covered in 1 second
    float distance = velocity * 1.0; // Assuming updates every 1 second
    //Convert distance to latitude/longitude changes
    float deltaLatitude = (distance / 111320.0); // Change in latitude in degrees
    float deltaLongitude = (distance / (111320.0 * cos(latitude * M_PI / 180.0))); // Change in longitude

    // Apply direction (bearing) using trigonometry
   
    latitude += deltaLatitude * cos(direction * M_PI / 180.0);
    longitude += deltaLongitude * sin(direction * M_PI / 180.0);
    // Location data length: 4+4+2+2+4 = 16 bytes
    packContent.push_back(16);  

    // Latitude/Longitude (IEEE-754 floats)
    uint8_t* latPtr = reinterpret_cast<uint8_t*>(&latitude);
    uint8_t* lonPtr = reinterpret_cast<uint8_t*>(&longitude);
    packContent.insert(packContent.end(), latPtr, latPtr + 4);
    packContent.insert(packContent.end(), lonPtr, lonPtr + 4);
     // Altitude (2 bytes little-endian)
    packContent.push_back(altitude & 0xFF);
    packContent.push_back((altitude >> 8) & 0xFF);
    // Velocity (2 bytes little-endian)
    packContent.push_back(velocity & 0xFF);
    packContent.push_back((velocity >> 8) & 0xFF);

    // Timestamp (4 bytes little-endian)
    uint32_t timestamp = getCurrentUnixTimestamp();
    uint8_t* timePtr = reinterpret_cast<uint8_t*>(&timestamp);
    packContent.insert(packContent.end(), timePtr, timePtr + 4);
    messageCount++;


    // here we need to constuct the wrapper under authentication, we can call the create wrapper and return the wrapper 
    // --- Authentication Wrapper ---
    packContent.push_back(0x02);
    std::vector<uint8_t> wrapper = initWrapper();  
    packContent.insert(packContent.end(), wrapper.begin(), wrapper.end());
    messageCount++;  // Wrapper is treated as a single message


   // --- System Message ---
    packContent.push_back(0x04);  // System message type
    packContent.push_back(4);     // System data length
    packContent.push_back(0x01);  // Status flags
    packContent.push_back(0x00);  // Reserved
    packContent.push_back(0x00);  // Reserved
    packContent.push_back(0x00);  // Reserved
    messageCount++;

     // --- Calculate Pack Length ---
    uint16_t packLength = packContent.size() + 1;  // +1 for message count
    f3411Message.push_back(packLength & 0xFF);
    f3411Message.push_back((packLength >> 8) & 0xFF);

     // Add Message Count
    f3411Message.push_back(messageCount);


    // Insert pack content
    f3411Message.insert(f3411Message.end(), packContent.begin(), packContent.end());
    
    return f3411Message;
}*/






// Function to Create Payload (F3411 Messages)
/*std::vector<uint8_t> createPayload() {
    std::vector<uint8_t> payload;
    // Generate F3411 message
    std::vector<uint8_t> f3411Message = generateF3411Message();
    // Add F3411 message to the payload
    payload.insert(payload.end(), f3411Message.begin(), f3411Message.end());
    // Print the payload for debugging
    printVectorHex(payload, "Payload (F3411 Messages)");

    return payload;
}*/



void clear_nvs() {
    esp_err_t err = nvs_flash_erase();
    if (err == ESP_OK) {
        printf("NVS erased successfully.\n");
    } else {
        printf("Failed to erase NVS: %s\n", esp_err_to_name(err));
    }

    err = nvs_flash_init();
    if (err == ESP_OK) {
        printf("NVS initialized successfully.\n");
    } else {
        printf("Failed to initialize NVS: %s\n", esp_err_to_name(err));
    }
}

void performOTAUpdate(const char* firmwareUrl) {
    WiFiClient client;
    HTTPClient http;

    Serial.println("Connecting to firmware URL...");
    http.begin(firmwareUrl);

    int httpCode = http.GET();
    if (httpCode == 200) {  // HTTP OK
        int contentLength = http.getSize();
        WiFiClient* stream = http.getStreamPtr();

        if (Update.begin(contentLength)) {
            size_t written = Update.writeStream(*stream);
            if (written == contentLength) {
                Serial.println("Firmware update completed.");
                if (Update.end()) {
                    Serial.println("Restarting...");
                    ESP.restart();
                } else {
                    Serial.println("Update failed: " + String(Update.getError()));
                }
            } else {
                Serial.println("Written bytes do not match content length.");
                Update.abort();
            }
        } else {
            Serial.println("Not enough space for OTA update.");
        }
    } else {
        Serial.println("Firmware download failed. HTTP code: " + String(httpCode));
    }
    http.end();
}










void clearCache() {
    esp_err_t err = nvs_flash_erase();
    if (err == ESP_OK) {
        Serial.println("NVS cache cleared successfully.");
    } else {
        Serial.printf("Failed to clear NVS cache: %s\n", esp_err_to_name(err));
    }
}


void checkForUpdates() {
    if (WiFi.status() == WL_CONNECTED) {
        HTTPClient http;
        http.begin(versionUrl);

        int httpCode = http.GET();
        if (httpCode == 200) {  // HTTP OK
            String payload = http.getString();
            DynamicJsonDocument doc(1024);
            DeserializationError error = deserializeJson(doc, payload);

            if (!error) {
                String latestVersion = doc["version"];
                String firmwareUrl = doc["firmware_url"];
                Serial.println("Latest version: " + latestVersion);
                Serial.println("Current version: " + currentVersion);

                if (latestVersion != currentVersion) {
                    Serial.println("New update available! Updating...");
                    performOTAUpdate(firmwareUrl.c_str());
                } else {
                    Serial.println("No updates available. Firmware is up-to-date.");
                }
            } else {
                Serial.print("JSON Parse Error: ");
                Serial.println(error.c_str());
            }
        } else {
            Serial.println("Failed to fetch update information. HTTP code: " + String(httpCode));
        }
        http.end();
    } else {
        Serial.println("WiFi not connected.");
    }
}


void NVSInit(){

   // Initialize NVS
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }


}













void InitTime() {
    configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
    
    struct tm timeInfo;
    if (!getLocalTime(&timeInfo)) {
        Serial.println("Failed to obtain time from NTP");
        return;
    }
    
    Serial.print("Time synchronized: ");
    Serial.printf("%04d-%02d-%02d %02d:%02d:%02d\n", 
                  timeInfo.tm_year + 1900, timeInfo.tm_mon + 1, timeInfo.tm_mday,
                  timeInfo.tm_hour, timeInfo.tm_min, timeInfo.tm_sec);
}




void WiFiInit(){

  // Connect to Wi-Fi
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(1000);
        Serial.println("Connecting to WiFi...");
    }
    Serial.println("Connected to WiFi.");



}











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
  .primary_phy = ESP_BLE_GAP_PHY_CODED,
  .max_skip = 0,
  .secondary_phy = ESP_BLE_GAP_PHY_CODED,
  .sid = 1,
  .scan_req_notif = false,
};


/*static uint8_t adv_data_with_wrapper[] = {
    0x02, 0x01, 0x06,
    0x05, 0xFF, 0x12, 0x34, 0x56, 0x78  // Short Manufacturer Data
};*/


/*static uint8_t adv_data_with_wrapper[] = {
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
   
};*/


/*static uint8_t wrapper[107] = {
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
*/





// GAP Event Handler
static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    switch (event) {
        case ESP_GAP_BLE_EXT_ADV_SET_PARAMS_COMPLETE_EVT:
            ESP_LOGI(LOG_TAG, "Advertising parameters set.");
            esp_ble_gap_ext_adv_set_rand_addr(0, addr_1m);
            break;
        case ESP_GAP_BLE_EXT_ADV_SET_RAND_ADDR_COMPLETE_EVT:
            ESP_LOGI(LOG_TAG, "Random address set.");
            esp_ble_gap_config_ext_adv_data_raw(0, fullPayload.size(), fullPayload.data());
            break;

        case ESP_GAP_BLE_EXT_ADV_DATA_SET_COMPLETE_EVT:
            ESP_LOGI(LOG_TAG, "Advertising data set. Starting extended advertising...");
            esp_ble_gap_ext_adv_start(1, ext_adv);
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


void generateRandomData(uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        data[i] = random(0, 256); // Generate random byte values
    }
}

// Main Application Entry Point
extern  "C" void app_main(void) {
    
    initArduino();
    NVSInit();
    clear_nvs();
    WiFiInit(); 
    InitTime();
    generateKeys();
    //initWrapper();
    constructASTMMessages(true);
    
// Check for updates
    checkForUpdates();


    while (wrapperCreated == false){
    ESP_LOGI(LOG_TAG, "Creating Wrapper");

    }

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));
    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());

    //ESP_LOGI(LOG_TAG, "Advertising Data Length: %d", broadcastMessage.size());
    ESP_ERROR_CHECK(esp_ble_gap_register_callback(gap_event_handler));
    esp_ble_gap_ext_adv_set_params(0, &ext_adv_params_2M);

     while (1) {
        ESP_LOGI(LOG_TAG, "Main loop running...");
  unsigned long currentTime = millis();
    if (currentTime - lastTransmissionTime >= transmissionInterval) {
        lastTransmissionTime = currentTime;
          ArduinoOTA.handle();
  // Convert std::string to Arduino String and print it
        Serial.println(String(toBinary(det.prefix, 28).c_str()));  // 28 bits for IPv6 Prefix
        Serial.println(String(toBinary(det.raa, 14).c_str()));  // 14 bits for RAA
        Serial.println(String(toBinary(det.hda, 14).c_str()));  // 14 bits for HDA
        Serial.println(String(toBinary(det.suiteID, 8).c_str()));  // 8 bits SUITID

        for (int i = 0; i< sizeof(privateKey); i++ ){
            Serial.print(privateKey[i]);
        }
          Serial.println();
           for (int i = 0; i< sizeof(publicKey); i++ ){
            Serial.print(publicKey[i]);
        }
                   

           // Print the payload vector in hex
      printVectorHex(dripLink, "DRIP LINK : ");       
         Serial.println();   
      printVectorHex(wrapper, "WRAPPER BEFORE SIGNING : ");  
         Serial.println(); 
   

           // Broadcast Wrapper over BLE
        Serial.println("Broadcasting Wrapper over BLE...");
    


      Serial.println("Wrapper Content (Signed, Byte-by-Byte):");
for (size_t i = 0; i < wrapper.size(); i++) {
    Serial.printf("%02X ", wrapper[i]);
}
Serial.println();

Serial.println("Signed Wrapper Content (ESP32):");
for (size_t i = 0; i < wrapper.size(); i++) {
    Serial.printf("%02X ", wrapper[i]);
}
Serial.println();

Serial.println("Generated UAV Signature:");
for (int i = 0; i < 64; i++) {
    Serial.printf("%02X ", signature[i]);
}
Serial.println();
Serial.println("Child DET: " + String(childDET.c_str()));
Serial.println("HDA DET: " + String(ParentDET.c_str()));

Serial.printf("Wrapper Length: %d\n", wrapper.size());

Serial.println("Generated UAV Signature Length: 64");  // Ed25519 signatures are always 64 bytes
    // Now verify the test signature
bool valid = Ed25519::verify(test_signature, publicKey, test_message, sizeof(test_message));
if (valid) {
    Serial.println("Key pair is valid on ESP32.");
} else {
    Serial.println("Key pair verification failed on ESP32.");
}

  String WrapperSTR = byteArrayToHexString(wrapper.data(), wrapper.size());
  std::string wrapperStdStr = WrapperSTR.c_str();


 // delay(500);
    //initWrapper();
    //generateF3411Message();
    constructASTMMessages(true);
 
    sendWrapperAndPublicKey();
    if (linkRec == true){
     // sendDripLink();
      //updateAdvDataWithWrapper(dripLink, dripLink.size(), true);
      constructASTMMessages(false);
    }

    // Update and broadcast the wrapper
        
            

    //esp_err_t ret = esp_ble_gap_config_ext_adv_data_raw(0, fullPayload.size(), fullPayload.data());
/*if (ret == ESP_OK) {
    printf("Advertising data updated successfully\n");
} else {
    printf("Failed to update advertising data: %s\n", esp_err_to_name(ret));
}*/
    }


        vTaskDelay(pdMS_TO_TICKS(1000));

    }
}
