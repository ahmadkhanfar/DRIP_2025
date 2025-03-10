# **Project Overview** #

**DRIP_2025** is an open-source project aimed at providing a comprehensive solution for Drone Remote Identification (Remote ID). It integrates hardware, mobile, and server components to enable drones to broadcast their identification and location information, and for observers to receive and verify this data in real-time. 

The project’s primary purpose is to demonstrate a working implementation of the Drone Remote ID Protocol and ensure compliance with industry standards for remote identification. Key functionalities include:

  * **Broadcast Module** (Drone-Mounted) <ins>: Firmware that allows a drone (or attached device) to broadcast its ID and telemetry (location, altitude, etc.) using Bluetooth and Wi-Fi signals following standard Remote ID formats.
  
  * **Mobile Receiver App**: A Flutter-based mobile application that scans for nearby drones’ broadcast signals, decodes the Remote ID messages, and displays pertinent information (e.g., drone ID, position, operator info). This app acts as a receiver and user interface for the system
  
  * **Backend Server and Database**: A server application (with a SQL database) that can collect Remote ID data, store registered drone and operator information, and provide an API for querying or verifying drone identities. This enables network-based retrieval of drone information and supports features like authentication or logging of drone flights.

Together, these components create an end-to-end system where a drone can be identified and tracked by authorized parties, promoting airspace awareness and regulatory compliance.





**Follow these steps to set up the DRIP_2025 project. There are multiple components (firmware, app, server), each with its own setup requirements:**

- Clone the Repository:
git clone https://github.com/ahmadkhanfar/DRIP_2025.git
- Embedded Firmware (ESP-IDF):
