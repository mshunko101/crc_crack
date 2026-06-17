/***************************************************************************
  This is a library for the BME680 gas, humidity, temperature & pressure sensor

  Designed specifically to work with the Adafruit BME680 Breakout
  ----> http://www.adafruit.com/products/3660

  These sensors use I2C or SPI to communicate, 2 or 4 pins are required
  to interface.

  Adafruit invests time and resources providing this open source code,
  please support Adafruit and open-source hardware by purchasing products
  from Adafruit!

  Written by Limor Fried & Kevin Townsend for Adafruit Industries.
  BSD license, all text above must be included in any redistribution
 ***************************************************************************/

#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_BME680.h>
#include <Zanshin_BME680.h>
#include <WiFiNINA.h>
#include <WiFiSSLClient.h>  // Добавляется автоматически с WiFiNINA 
void resetBoard() ;
///////please enter your sensitive data in the Secret tab/arduino_secrets.h
char ssid[] = "MISHAIL";        // your network SSID (name)
char pass[] = "misha_superman";    // your network password (use for WPA, or use as key for WEP)
int keyIndex = 0;            // your network key index number (needed only for WEP)

int status = WL_IDLE_STATUS;
// if you don't want to use DNS (and reduce your sketch size)
// use the numeric IP instead of the name for the server:
//IPAddress server(74,125,232,128);  // numeric IP for Google (no DNS)
 
// Initialize the Ethernet client library
// with the IP address and port of the server
// that you want to connect to (port 80 is default for HTTP):
WiFiClient client;


// Настройки сервера
const char* serverName = "xn--80aah6bn6b.xn--90ais";  // Или IP сервера
const int serverPort = 80;                    // Порт (80 для HTTP)

// Секретный пароль для PHP‑скрипта (как в $secretPassword)
const String scriptPassword = "222852t710ph_root_1";
 
 

#define BME_SCK 9
#define BME_MISO 10
#define BME_MOSI 8
#define BME_CS 1
 
Adafruit_BME680 bme(BME_CS, BME_MOSI, BME_MISO, BME_SCK);
 
BME680_Class  BME680;

// Интервалы
unsigned long lastRead = 0;
unsigned long lastReadRead = 0;
const long readInterval = 10;  // 5 Мин между измерениями
const long writeInterval = 1000;
// Параметры модели (можно менять) 
const double L = 25.0;          // Линейный размер (диаметр сферы), м
const double alphaConst = 0.00834;   // Масса системы, кг (для контекста модели)

// Переменные для уравнений
float x1 = 0.0;  // температура (°C)
float x2 = 0.0;  // влажность (%)
float x3 = 0.0;  // IAQ (0–500)

bool sendHttpRequest(String postData);
// Пороговые значения невязок
const float TOLERANCE = 5.0;  // допуск на отклонение

void setup() {
   
 // Serial.begin(9600);
 // while (!Serial);
  pinMode(LED_BUILTIN, OUTPUT);
  // Инициализация BME688
  if (!bme.begin(0x76)) {
    Serial.println("Ошибка: не найден BME688!");
    while (!bme.begin(0x76));
  }
 
  // Настройка BSEC (упрощённая)
// Настройка параметров (например, oversampling и фильтрация)
  BME680.setOversampling(TemperatureSensor, Oversample16);
  BME680.setOversampling(HumiditySensor, Oversample16);
  BME680.setOversampling(PressureSensor, Oversample16);
  BME680.setIIRFilter(IIR4);
  BME680.setGas(320, 150); // Настройка измерения газа при 320°C в течение 150 мс

  
}
float prev;
float normalizeGasToIAQ(int32_t gas_ohm, float temp_c, float hum_pct);
 
void loop() {

 if (Serial.available() > 0) { // Если пришло что-то от ПК
    char inChar = Serial.read();
    if (inChar == 'G') { // Например, команда 'G' = "Give data"
     
      // Отправляем структурированный пакет
 
    //Serial.print('GAS:');
    Serial.print((x3)); 
    Serial.println();
    }
  }
        // Считываем данные с BME688
    if (!bme.performReading()) {
      Serial.println("Ошибка чтения датчика");
    
      return;
    }
    x1 = bme.temperature;   // x₁ — температура
    x2 = bme.humidity;     // x₂ — влажность
    x3 = bme.gas_resistance;
  //  int32_t temperature, humidity, pressure, gas;
    //BME680.getSensorData(temperature, humidity, pressure, gas,true);
 
    x3 = normalizeGasToIAQ(x3, x1, x2);
    delay(1000);
    
}

// Функция нормализации сопротивления газа к условной шкале IAQ (0–500)
float normalizeGasToIAQ(int32_t gas_ohm, float temp_c, float hum_pct) {
 
  const float MIN_RES = 5000.0;   // Ом, «чистый воздух»
  const float MAX_RES = 500000.0; // Ом, «сильное загрязнение»

  float norm_res = (float)(gas_ohm - MIN_RES) / (MAX_RES - MIN_RES);
  norm_res = max(0.0, min(1.0, norm_res)); // Ограничиваем 0..1
  return 500.0 * norm_res; // Переводим в шкалу 0–500
 
}
  
 

