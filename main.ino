#include <ArduinoJson.h>
#include <ArduinoJson.hpp>

/* CODED BY AHMAD K. KHANFAR, 

THE CODE WILL GENERATE DET 128 bit, Wrappers, and DRIP Links*/
#include <Ed25519.h>
#include <RNG.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <vector>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <BLE2902.h>
#include <bitset>
#include <iostream>
#include <KeccakP-1600-SnP.h>
#include "KeccakP-1600-inplace32BI.c"
#include <WiFi.h>
#include <time.h>  // For Unix timestamps
#include <HTTPClient.h>
#include <ArduinoOTA.h>
#include <Arduino.h>
#define DEVICE_NAME "BT5-Drone"

unsigned long dripLinkCreationTime;// Global variable to store DRIP Link creation time

unsigned long HDATime;
unsigned long detGenerationTime;    // For DET generation timing
unsigned long wrapperCreationTime;  // For Wrapper creation timing

using namespace std;
uint8_t test_message[] = "Test message for signing";
uint8_t test_signature[64];
int hda = 177;
#define CHARACTERISTC_UUID_TX "6E400003-B5A3-F303-E0A9-E50E24DCCA9E"
#define CHARACTERISTIC_UUID_DRIP_LINK "6E400004-B5A3-F303-E0A9-E50E24DCCA9E"


#define SERVICE_UUID "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"

bool linkRec = false;

uint8_t parentDETArray[16];
uint8_t childDETArray[16];

// Wi-Fi Credentials
const char* ssid = "Khanfar";
const char* password = "khalid123";
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


BLECharacteristic *pCharacteristic; 
BLECharacteristic *pDripLinkCharacteristic;

uint32_t parentVNB; 

uint32_t parentVNA;

bool deviceConnected = false; 

 int loops = -1; 

// Defining Parent DET as custom for now 
// DET (16 bytes) stored as a uint8_t array
std:: string childDET; 
std:: string ParentDET;
uint8_t signature[64];
uint8_t parentSignature[64];
std::vector<uint8_t> wrapper;
std::vector<uint8_t> dripLink;
unsigned long lastTransmissionTime = 0;  // To manage timed transmissions
const unsigned long transmissionInterval = 5000;  // 5 seconds
// Function to convert an unsigned int to a binary string with leading zeros
std::string toBinary(unsigned int value, int bits) {
    return std::bitset<64>(value).to_string().substr(64 - bits, bits);  // Convert and trim to required bits
}

// Helper function to insert 32-bit Unix timestamp into a vector (little-endian format)
void insertUnixTimestamp(std::vector<uint8_t>& vec, uint32_t timestamp) {
    for (int i = 0; i < 4; i++) {
        vec.push_back((uint8_t)(timestamp >> (8 * i)));  // Little-endian order
    }
}


uint32_t getCurrentUnixTimestamp() {
    time_t now;
    time(&now);  // Get the current time in seconds since the epoch
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
uint8_t contextID[] = { 0x00B5, 0xA69C, 0x795D, 0xF5D5, 0xF008, 0x7F56, 0x843F, 0x2C40 };  // Context ID for DET
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





std::vector<uint8_t> createWrapper(
    const std::vector<uint8_t> &payload, const uint8_t *det) {

      unsigned long startWrapper = millis();
    wrapper.clear(); // Clear existing wrapper data

      // Get the current Unix timestamps
    uint32_t validNotBefore = getCurrentUnixTimestamp();  // Now
    
    wrapper.insert(wrapper.end(), (uint8_t*)&validNotBefore, (uint8_t*)&validNotBefore + 4);
    
    uint32_t validNotAfter = validNotBefore + 300;  // Valid for 5 minutes

    wrapper.insert(wrapper.end(), (uint8_t*)&validNotAfter, (uint8_t*)&validNotAfter + 4);

    // Add payload (F3411 messages, 25–100 bytes)
    wrapper.insert(wrapper.end(), payload.begin(), payload.end());

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


esp_ble_gap_ext_adv_params_t ext_adv_params = {
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




    // Example Manufacturer Data
// Example Manufacturer Data

// Device Name
static uint8_t raw_scan_rsp_data_2m[] = {
    0x0F, 0x09,             // Length and Type: Complete Local Name
    'K', 'h', 'a', 'n', 'f', 'a', 'r', ' ', 'D', 'r', 'o', 'n', 'e'
};

// Service UUID Data
static uint8_t service_uuid_data[] = {
    0x11, 0x07,                    // Length and Type for 128-bit Service UUID
    0x6E, 0x40, 0x00, 0x01, 0xB5,  // Example Service UUID
    0xA3, 0xF3, 0x93, 0xE0, 0xA9,
    0xE5, 0x0E, 0x24, 0xDC, 0xCA,
    0x9E
};

static uint8_t device_name[] = {
    0x0F, 0x09, // Length and Type
    'K', 'h', 'a', 'n', 'f', 'a', 'r', ' ', 'D', 'r', 'o', 'n', 'e'
};





uint8_t addr_2m[6] = {0xC0, 0xDE, 0x52, 0x00, 0x00, 0x02};

BLEMultiAdvertising advert(1);
// Manufacturer Data (Include DET)
uint8_t manufacturer_data[] = {
    0xD1,                               // OpCode for DET
    0x20, 0x01, 0x00, 0x03,             // Prefix (IPv6, 28 bits)
    0x00, 0x03,                         // RAA (14 bits)
    0x00, 0x01,                         // HDA (14 bits)
    0x05,                               // Suite ID (8 bits)
    0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, // Public Key Hash (8 bytes - example)
    0x78, 0x90, 0x11, 0x22,             // Public Key Hash continued
};

// Device Name
uint8_t scan_rsp_data[] = {
    0x0F, 0x09,                          // Length and type for complete local name
    'K', 'h', 'a', 'n', 'f', 'a', 'r',   // Device Name
    ' ', 'D', 'r', 'o', 'n', 'e', '\0'   // End with NULL terminator
};

void initializeBLE() {
  
    // Initialize BLE Device
    BLEDevice::init("Khanfar Drone");

    // Set Extended Advertising Parameters
    esp_err_t err = esp_ble_gap_ext_adv_set_params(0, &ext_adv_params);
    if (err != ESP_OK) {
        Serial.printf("Failed to set extended advertising parameters: %s\n", esp_err_to_name(err));
        return;
    }

    // Configure Manufacturer Data
    err = esp_ble_gap_config_ext_adv_data_raw(0, sizeof(manufacturer_data), manufacturer_data);
    if (err != ESP_OK) {
        Serial.printf("Failed to set manufacturer data: %s\n", esp_err_to_name(err));
        return;
    }

        // Configure Manufacturer Data
    err = esp_ble_gap_config_ext_scan_rsp_data_raw(0, sizeof(scan_rsp_data), scan_rsp_data);
    if (err != ESP_OK) {
        Serial.printf("Failed to set data raw: %s\n", esp_err_to_name(err));
        return;
    }
    // Start Extended Advertising
    err = esp_ble_gap_ext_adv_start(0, 0);
    if (err == ESP_OK) {
        Serial.println("Extended BLE advertising started successfully.");
    } else {
        Serial.printf("Failed to start extended BLE advertising: %s\n", esp_err_to_name(err));
    }

  advert.setInstanceAddress(0, addr_2m);
  advert.setDuration(0, 0, 0);

  delay(100);
  advert.start();

}

// Function to generate F3411 data (example values)
std::vector<uint8_t> generateF3411Message() {
    std::vector<uint8_t> f3411Message;

    // Example F3411 fields (latitude, longitude, altitude, velocity, etc.)
    uint32_t latitude = 374221234;  // Example: 37.4221234 degrees
    uint32_t longitude = -122084000; // Example: -122.084000 degrees
    uint16_t altitude = 100;       // Example: 100 meters
    uint16_t velocity = 50;        // Example: 50 m/s
    uint32_t timestamp = getCurrentUnixTimestamp();

    // Add data to F3411 message in little-endian format
    f3411Message.insert(f3411Message.end(), (uint8_t *)&latitude, (uint8_t *)&latitude + sizeof(latitude));
    f3411Message.insert(f3411Message.end(), (uint8_t *)&longitude, (uint8_t *)&longitude + sizeof(longitude));
    f3411Message.insert(f3411Message.end(), (uint8_t *)&altitude, (uint8_t *)&altitude + sizeof(altitude));
    f3411Message.insert(f3411Message.end(), (uint8_t *)&velocity, (uint8_t *)&velocity + sizeof(velocity));
    f3411Message.insert(f3411Message.end(), (uint8_t *)&timestamp, (uint8_t *)&timestamp + sizeof(timestamp));

    return f3411Message;
}




// Function to Create Payload (F3411 Messages)
std::vector<uint8_t> createPayload() {
    std::vector<uint8_t> payload;
    // Generate F3411 message
    std::vector<uint8_t> f3411Message = generateF3411Message();
    // Add F3411 message to the payload
    payload.insert(payload.end(), f3411Message.begin(), f3411Message.end());
    // Print the payload for debugging
    printVectorHex(payload, "Payload (F3411 Messages)");

    return payload;
}


void initWrapper(){

    // Setup the constat values. :
    det.prefix = 0x2001003; 
    det.raa = 16376; 
    det.hda = 1025;
    det.suiteID = 5; 
    defineWrapper();
    initializeBLE();

     

}
  void defineWrapper (){


   

        unsigned long startDET = millis();
       childDET =  det_orchid (det.hda, det.raa, det.prefix, det.suiteID, publicKey,false);
        // Convert std::string DETs to uint8_t arrays
        unsigned long endDET = millis();
        detGenerationTime = endDET - startDET;
        uint8_t childDETArray[16];
        hexStringToByteArray(childDET, childDETArray, sizeof(childDETArray));

       std::vector<uint8_t> payload = createPayload();
         // Create Wrapper
      
        std::vector<uint8_t> wrapper = createWrapper(payload, childDETArray);
        

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
    Serial.printf("Using cached Parent VNA: %u\n", parentVNA);
    Serial.printf("Using cached Parent VNB: %u\n", parentVNB);
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
                Serial.printf("Parent VNA: %u\n", parentVNA);
                Serial.printf("Parent VNB: %u\n", parentVNB);


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


void NVSInit(){

   // Initialize NVS
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }


}



bool storeUint32ToCache(const char* key, uint32_t value) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("cache", NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        err = nvs_set_u32(handle, key, value);
        if (err == ESP_OK) {
            Serial.printf("Successfully stored key '%s' with value %u in cache.\n", key, value);
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

bool getUint32FromCache(const char* key, uint32_t* value) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("cache", NVS_READONLY, &handle);
    if (err == ESP_OK) {
        err = nvs_get_u32(handle, key, value);
        if (err == ESP_OK) {
            Serial.printf("Successfully retrieved key '%s' with value %u from cache.\n", key, *value);
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





void InitTime(){

// Initialize time from NTP server
    configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);

    // Wait for time to be set
    struct tm timeInfo;
    if (!getLocalTime(&timeInfo)) {
        Serial.println("Failed to obtain time");
        return;
    }

    Serial.println("Time synchronized:");
    Serial.println(&timeInfo, "%Y-%m-%d %H:%M:%S");

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




void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
 
  NVSInit();

  WiFiInit(); 
  generateKeys();
  initWrapper();
  

    //Sent to the Server the DET to register it. 

// Check for updates
    checkForUpdates();
  
}


void generateRandomData(uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        data[i] = random(0, 256); // Generate random byte values
    }
}

void loop() {

    Serial.printf("DET Generation Time: %lu ms\n", detGenerationTime);
    Serial.printf("Wrapper Creation Time: %lu ms\n", wrapperCreationTime);
    if (!dripLink.empty()) {
    Serial.printf("DRIP Link Creation Time: %lu ms\n", dripLinkCreationTime);
     Serial.printf(" HDA Time: %lu ms\n",  HDATime);
   
}

Serial.println("This is version 1.3 of the firmware.");

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


  delay(500);

    sendWrapperAndPublicKey();

    if (linkRec = true){
      sendDripLink();
    }




    


    }




}
