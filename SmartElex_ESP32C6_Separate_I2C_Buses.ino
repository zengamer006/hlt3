// ============================================================
// SINGLE SmartElex ESP32-C6-Mini-1-N4 Pico sensor transmitter
// Sensors: MPU6050, BMP280, AD8232 ECG, HX711 load cell,
//          analog water-level sensor, DS18B20
// Communication: ESP-NOW + existing crypto_utils.h encryption
//
// Pin mapping supplied by user:
// I2C bus 1 (MPU6050): SDA=GPIO2, SCL=GPIO3
// I2C bus 2 (BMP280 candidate): SDA=GPIO10, SCL=GPIO11
// AD8232 OUT=D0/GPIO0, LO+=D18/GPIO18, LO-=D19/GPIO19
// Water level=D1/GPIO1; DS18B20=D14/GPIO14
// HX711 DT=D6/GPIO6, SCK=D7/GPIO7
// BMP180 is NOT included. BMP280 only.
// ============================================================

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <Wire.h>
#include <Adafruit_BMP280.h>
#include <HX711.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include <math.h>
#include <string.h>
#include "crypto_utils.h"   // Keep the same encryption helper used by your source code

// ---------------- PIN DEFINITIONS ----------------
#define MPU_I2C_SDA_PIN  2
#define MPU_I2C_SCL_PIN  3
#define BMP_I2C_SDA_PIN  10  // Verify GPIO10 is exposed/free on your board
#define BMP_I2C_SCL_PIN  11  // Verify GPIO11 is exposed/free on your board
#define MPU_ADDR          0x68

#define ECG_OUTPUT_PIN    0
#define ECG_LO_PLUS_PIN   18
#define ECG_LO_MINUS_PIN  19

#define WATER_LEVEL_PIN   1
#define DS18B20_PIN       14

#define HX711_DOUT_PIN    6
#define HX711_SCK_PIN     7

// ---------------- ESP-NOW RECEIVER MAC ----------------
// Retained from the provided reference code. Change only if your
// receiver board has a different MAC address.
uint8_t receiverMAC[] = {0x1C, 0xDB, 0xD4, 0x42, 0x4E, 0xD4};

// ---------------- SENSOR OBJECTS ----------------
TwoWire BMPWire(1);  // Second I2C controller; may not be supported by this board/core
Adafruit_BMP280 bmp(&BMPWire);
HX711 scale;
OneWire oneWire(DS18B20_PIN);
DallasTemperature ds18b20(&oneWire);
CryptoCtx crypto;

bool mpuFound = false;
bool bmpFound = false;
bool scaleFound = false;

// ---------------- SENSOR STRUCTS ----------------
struct MPU6050Data {
  float ax, ay, az;
  float gx, gy, gz;
};

struct __attribute__((packed)) SensorData {
  // MPU6050
  float mpuAccelX;
  float mpuAccelY;
  float mpuAccelZ;
  float mpuGyroX;
  float mpuGyroY;
  float mpuGyroZ;

  // AD8232 ECG raw ADC value; zero when leads are disconnected
  float ecgValue;

  // HX711 output using existing calibration factor
  float loadCellWeight;

  // Analog water-level sensor raw ADC value
  float waterLevel;

  // DS18B20 actual temperature in Celsius; NAN if unavailable
  float ds18b20Temp;

  // BMP280
  float bmp280TemperatureC;
  float bmp280PressureHpa;
  float bmp280AltitudeM;

  uint32_t uptime;
};

#define SEALED_SIZE (sizeof(SensorData) + CRYPTO_PACKET_OVERHEAD)
struct __attribute__((packed)) DynamicPacket {
  uint8_t magic;
  uint8_t version;
  uint8_t txId;
  uint16_t encryptedLength;
  uint8_t encryptedData[SEALED_SIZE];
};

// ---------------- MPU6050 HELPERS ----------------
void writeMPUReg(uint8_t reg, uint8_t value) {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(reg);
  Wire.write(value);
  Wire.endTransmission();
}

void initializeMPU6050() {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(0x75); // WHO_AM_I
  if (Wire.endTransmission(false) != 0 || Wire.requestFrom((uint8_t)MPU_ADDR, (uint8_t)1) != 1) {
    Serial.println("[MPU6050] Not detected at I2C address 0x68.");
    return;
  }
  uint8_t id = Wire.read();
  if (id != 0x68 && id != 0x69) {
    Serial.printf("[MPU6050] Unexpected WHO_AM_I: 0x%02X\n", id);
    return;
  }
  writeMPUReg(0x6B, 0x00); // Wake up
  writeMPUReg(0x1C, 0x00); // Accelerometer +/-2 g
  writeMPUReg(0x1B, 0x00); // Gyroscope +/-250 deg/s
  delay(100);
  mpuFound = true;
  Serial.println("[MPU6050] Initialized.");
}

bool readMPU6050(MPU6050Data &d) {
  if (!mpuFound) return false;
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(0x3B);
  if (Wire.endTransmission(false) != 0) return false;
  if (Wire.requestFrom((uint8_t)MPU_ADDR, (uint8_t)14) != 14) return false;

  int16_t ax = (int16_t)((Wire.read() << 8) | Wire.read());
  int16_t ay = (int16_t)((Wire.read() << 8) | Wire.read());
  int16_t az = (int16_t)((Wire.read() << 8) | Wire.read());
  (void)Wire.read(); (void)Wire.read(); // Skip internal temperature registers
  int16_t gx = (int16_t)((Wire.read() << 8) | Wire.read());
  int16_t gy = (int16_t)((Wire.read() << 8) | Wire.read());
  int16_t gz = (int16_t)((Wire.read() << 8) | Wire.read());

  d.ax = ax / 16384.0f;
  d.ay = ay / 16384.0f;
  d.az = az / 16384.0f;
  d.gx = gx / 131.0f;
  d.gy = gy / 131.0f;
  d.gz = gz / 131.0f;
  return true;
}

// ---------------- ENCRYPTION DEVICE ID ----------------
void createDeviceID(uint8_t deviceID[16]) {
  memset(deviceID, 0, 16);
  uint64_t chipID = ESP.getEfuseMac();
  for (int i = 0; i < 8; ++i) {
    deviceID[i] = (uint8_t)((chipID >> (56 - (i * 8))) & 0xFF);
  }
  memcpy(&deviceID[8], "EDMONIT2", 8);
}

// Arduino-ESP32 core 3.x callback signature
void onDataSent(const wifi_tx_info_t *info, esp_now_send_status_t status) {
  (void)info;
  Serial.println(status == ESP_NOW_SEND_SUCCESS ? "[ESP-NOW] Send success" : "[ESP-NOW] Send failed");
}

// ---------------- SETUP ----------------
void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== SmartElex ESP32-C6: Combined Sensor Transmitter ===");

  // I2C bus 1: MPU6050 on GPIO2/GPIO3
  Wire.begin(MPU_I2C_SDA_PIN, MPU_I2C_SCL_PIN);
  Wire.setClock(100000);
  Serial.println("[I2C-1] MPU6050 SDA=GPIO2, SCL=GPIO3");

  // I2C bus 2: BMP280 on GPIO10/GPIO11 (candidate pins)
  bool bmpBusStarted = BMPWire.begin(BMP_I2C_SDA_PIN, BMP_I2C_SCL_PIN, 100000);
  if (bmpBusStarted) {
    Serial.println("[I2C-2] BMP280 SDA=GPIO10, SCL=GPIO11");
  } else {
    Serial.println("[I2C-2] Second I2C bus failed to start; this ESP32-C6 Arduino core/board may not support TwoWire(1).");
  }

  // ADC setup
  analogReadResolution(12);
  analogSetPinAttenuation(ECG_OUTPUT_PIN, ADC_11db);
  analogSetPinAttenuation(WATER_LEVEL_PIN, ADC_11db);
  pinMode(ECG_OUTPUT_PIN, INPUT);
  pinMode(ECG_LO_PLUS_PIN, INPUT);
  pinMode(ECG_LO_MINUS_PIN, INPUT);
  pinMode(WATER_LEVEL_PIN, INPUT);

  initializeMPU6050();

  // BMP280 only; try standard BMP280 addresses on bus 2
  if (bmpBusStarted) {
    bmpFound = bmp.begin(0x76);
    if (!bmpFound) bmpFound = bmp.begin(0x77);
  }
  if (bmpFound) {
    bmp.setSampling(Adafruit_BMP280::MODE_NORMAL,
                    Adafruit_BMP280::SAMPLING_X2,
                    Adafruit_BMP280::SAMPLING_X16,
                    Adafruit_BMP280::FILTER_X16,
                    Adafruit_BMP280::STANDBY_MS_500);
    Serial.println("[BMP280] Initialized.");
  } else {
    Serial.println("[BMP280] Not detected at 0x76 or 0x77. Check wiring/address.");
  }

  // HX711 - retains calibration factor from supplied TX2 source
  scale.begin(HX711_DOUT_PIN, HX711_SCK_PIN);
  Serial.println("[HX711] Initializing...");
  delay(500);
  if (scale.is_ready()) {
    scale.set_scale(420.0f);
    delay(100);
    scale.tare();
    scaleFound = true;
    Serial.println("[HX711] Ready; calibration factor = 420.0; tare complete.");
  } else {
    Serial.println("[HX711] Not ready. Check DT/SCK and power.");
  }

  // DS18B20
  ds18b20.begin();
  ds18b20.setResolution(11);
  Serial.printf("[DS18B20] Devices found: %d\n", ds18b20.getDeviceCount());

  // ESP-NOW
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  Serial.print("[Wi-Fi] This board MAC: ");
  Serial.println(WiFi.macAddress());

  if (esp_now_init() != ESP_OK) {
    Serial.println("[ESP-NOW] Initialization failed.");
    return;
  }
  esp_now_register_send_cb(onDataSent);

  esp_now_peer_info_t peerInfo = {};
  memcpy(peerInfo.peer_addr, receiverMAC, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false; // Application payload is sealed by CryptoCtx below
  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    Serial.println("[ESP-NOW] Failed to add receiver peer.");
  } else {
    Serial.println("[ESP-NOW] Receiver peer added.");
  }

  uint8_t devId[16];
  createDeviceID(devId);
  crypto.init(devId);

  Serial.println("[READY] Single combined sensor node is online.");
}

// ---------------- MAIN LOOP ----------------
void loop() {
  static uint32_t lastSend = 0;
  if (millis() - lastSend < 1000) {
    delay(5);
    return;
  }
  lastSend = millis();

  SensorData data = {};
  data.ds18b20Temp = NAN;
  data.bmp280TemperatureC = NAN;
  data.bmp280PressureHpa = NAN;
  data.bmp280AltitudeM = NAN;

  // 1) MPU6050
  MPU6050Data mpu = {};
  bool mpuOK = readMPU6050(mpu);
  if (mpuOK) {
    data.mpuAccelX = mpu.ax; data.mpuAccelY = mpu.ay; data.mpuAccelZ = mpu.az;
    data.mpuGyroX = mpu.gx; data.mpuGyroY = mpu.gy; data.mpuGyroZ = mpu.gz;
  }

  // 2) AD8232 ECG: raw ADC count; lead-off pins HIGH means disconnected
  bool leadsConnected = (digitalRead(ECG_LO_PLUS_PIN) == LOW && digitalRead(ECG_LO_MINUS_PIN) == LOW);
  if (leadsConnected) data.ecgValue = (float)analogRead(ECG_OUTPUT_PIN);
  else data.ecgValue = 0.0f;

  // 3) HX711 load cell
  if (scaleFound && scale.is_ready()) data.loadCellWeight = scale.get_units(1);
  else data.loadCellWeight = NAN;

  // 4) Analog water-level sensor: raw 12-bit ADC reading
  data.waterLevel = (float)analogRead(WATER_LEVEL_PIN);

  // 5) DS18B20 actual sensor temperature
  ds18b20.requestTemperatures();
  float t = ds18b20.getTempCByIndex(0);
  if (t != DEVICE_DISCONNECTED_C && isfinite(t) && t >= -55.0f && t <= 125.0f) data.ds18b20Temp = t;

  // 6) BMP280
  if (bmpFound) {
    data.bmp280TemperatureC = bmp.readTemperature();
    data.bmp280PressureHpa = bmp.readPressure() / 100.0f;
    data.bmp280AltitudeM = bmp.readAltitude(1013.25f); // sea-level pressure default; calibrate for location
  }

  data.uptime = millis();

  // Serial telemetry
  Serial.println("\n----------- SENSOR TELEMETRY -----------");
  if (mpuOK) {
    Serial.printf("MPU6050 Accel (g): X=%.3f Y=%.3f Z=%.3f\n", data.mpuAccelX, data.mpuAccelY, data.mpuAccelZ);
    Serial.printf("MPU6050 Gyro (deg/s): X=%.2f Y=%.2f Z=%.2f\n", data.mpuGyroX, data.mpuGyroY, data.mpuGyroZ);
  } else Serial.println("MPU6050: unavailable/read error");

  Serial.printf("AD8232 ECG raw: %.0f (%s)\n", data.ecgValue, leadsConnected ? "leads connected" : "lead-off detected");
  if (isfinite(data.loadCellWeight)) Serial.printf("HX711 weight: %.2f (scale units; calibrate to grams/kg)\n", data.loadCellWeight);
  else Serial.println("HX711: unavailable/not ready");
  Serial.printf("Water sensor ADC: %.0f / 4095\n", data.waterLevel);
  if (isfinite(data.ds18b20Temp)) Serial.printf("DS18B20: %.2f C\n", data.ds18b20Temp);
  else Serial.println("DS18B20: not detected/invalid");
  if (bmpFound) {
    Serial.printf("BMP280 temperature: %.2f C\n", data.bmp280TemperatureC);
    Serial.printf("BMP280 pressure: %.2f hPa\n", data.bmp280PressureHpa);
    Serial.printf("BMP280 approximate altitude: %.2f m\n", data.bmp280AltitudeM);
  } else Serial.println("BMP280: unavailable");
  Serial.printf("Uptime: %lu ms\n", (unsigned long)data.uptime);

  // Seal and send packet, preserving the provided source's crypto format
  DynamicPacket packet = {};
  packet.magic = 0xAB;
  packet.version = 1;
  packet.txId = 2; // Identifier retained for compatibility with your existing receiver
  size_t encLen = 0;
  crypto.seal(reinterpret_cast<const uint8_t*>(&data), sizeof(data),
              millis() / 1000, packet.encryptedData, encLen);
  if (encLen == 0 || encLen > sizeof(packet.encryptedData)) {
    Serial.println("[CRYPTO] Invalid encrypted length; packet not sent.");
    return;
  }
  packet.encryptedLength = (uint16_t)encLen;
  esp_err_t result = esp_now_send(receiverMAC, reinterpret_cast<uint8_t*>(&packet), 5 + encLen);
  if (result != ESP_OK) Serial.printf("[ESP-NOW] Send call failed: %d\n", (int)result);
}
