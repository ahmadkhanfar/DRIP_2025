# **Project Overview** #

**DRIP_2025** is an open-source project aimed at providing a comprehensive solution for Drone Remote Identification (Remote ID). It integrates hardware, mobile, and server components to enable drones to broadcast their identification and location information, and for observers to receive and verify this data in real-time. 

The project’s primary purpose is to demonstrate a working implementation of the Drone Remote ID Protocol and ensure compliance with industry standards for remote identification. Key functionalities include:

  * **Broadcast Module** (Drone-Mounted) <ins>: Firmware that allows a drone (or attached device) to broadcast its ID and telemetry (location, altitude, etc.) using Bluetooth and Wi-Fi signals following standard Remote ID formats.
  
  * **Mobile Receiver App**: A Flutter-based mobile application that scans for nearby drones’ broadcast signals, decodes the Remote ID messages, and displays pertinent information (e.g., drone ID, position, operator info). This app acts as a receiver and user interface for the system
  
  * **Backend Server and Database**: A server application (with a SQL database) that can collect Remote ID data, store registered drone and operator information, and provide an API for querying or verifying drone identities. This enables network-based retrieval of drone information and supports features like authentication or logging of drone flights.

Together, these components create an end-to-end system where a drone can be identified and tracked by authorized parties, promoting airspace awareness and regulatory compliance.





**Follow these steps to set up the DRIP_2025 project. There are multiple components (firmware, app, server), each with its own setup requirements:**

1.  Clone the Repository:
`git clone https://github.com/ahmadkhanfar/DRIP_2025.git`
2.  Embedded Firmware (ESP-IDF):
   - Prerequisites: Install the Espressif ESP-IDF development framework (ESP-IDF) for ESP32 hardware. Follow Espressif’s setup guide to install the toolchain and ESP-IDF environment (ensure you can run idf.py from the command line).
   - Configure Hardware: Connect your ESP32 development board to your computer. Ensure drivers are installed and note the COM/serial port.
   - Build and Flash: Navigate to the ESP-IDF/ directory in the repositor
     - `cd DRIP_2025/ESP-IDF`
   - Set the target (if required) and build the firmware:
     - `idf.py set-target esp32`
     - `idf.py build`
   - After a successful build, flash the firmware to the ESP32:
     - `idf.py flash` <br>
You can also monitor the device log output with `idf.py monitor` to verify it’s broadcasting as expected. <br>
The firmware will automatically start broadcasting the drone’s Remote ID data via Bluetooth 5 once the board is reset or powered on.

3. Mobile App (Flutter):
- Prerequisites: Install Flutter SDK (stable channel) and ensure you have an Android device or emulator set up. (The app is cross-platform, but testing on Android is recommended for Bluetooth scanning capabilities.)
- Dependencies: Navigate to the Flutter/ directory and fetch dependencies:
  - `cd ../Flutter`
  - `flutter pub get`
- Run the App: Connect your Android device via USB (or start an emulator), ensure it’s detected (flutter devices), then launch the app:
  - `flutter run` 
 <br>
This will build and install the DRIP_2025 app on your device. Upon launching, grant any necessary permissions (location/Bluetooth) so the app can scan for Remote ID broadcasts. <br>
**Note:** The Flutter app uses device Bluetooth and Wi-Fi radios to receive drone ID broadcasts. Ensure your device supports Bluetooth 4.0+ (for BLE) and Wi-Fi if required by the standard.



