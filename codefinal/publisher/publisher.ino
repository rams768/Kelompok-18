#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <LiquidCrystal_I2C.h>
LiquidCrystal_I2C lcd(0x27, 16, 2);

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "crypto_aead.h"
#include "romulus_m.h"
#include "skinny.h"
#include "variant.h"

#define MAX_MSG_LENGTH 1024
#define AD_BLK_LEN_EVN 16

    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char nonce[CRYPTO_NPUBBYTES];
    unsigned char plaintext[MAX_MSG_LENGTH];
    unsigned char ciphertext[MAX_MSG_LENGTH + CRYPTO_ABYTES];
    unsigned char ad[AD_BLK_LEN_EVN] = "1234";
    unsigned long long plaintext_len, ad_len, ciphertext_len;

    

// Update these with values suitable for your network.
const char* ssid = "Rama";
const char* password = "11111111";
const char* mqtt_server = "broker.mqtt-dashboard.com";

unsigned long previousMillisGetHR = 0; //--> will store the last time Millis (to get Heartbeat) was updated.
unsigned long previousMillisHR = 0; //--> will store the last time Millis (to get BPM) was updated.

const long intervalGetHR = 10; //--> Interval for reading heart rate (Heartbeat) = 10ms.
const long intervalHR = 3000; //--> Interval for obtaining the BPM value based on the sample is 3 seconds.

const int PulseSensorHRWire = A0; //--> PulseSensor connected to ANALOG PIN 0 (A0 / ADC 0).
const int LED_D6 = D6; //--> LED to detect when the heart is beating. The LED is connected to PIN D1 (GPIO5) on the NodeMCU ESP12E.
int Threshold = 600; //--> Determine which Signal to "count as a beat" and which to ignore.

int cntHB = 0; //--> Variable for counting the number of heartbeats.
boolean ThresholdStat = true; //--> Variable for triggers in calculating heartbeats.
int BPMval = 0; //--> Variable to hold the result of heartbeats calculation.

WiFiClient espClient;
PubSubClient client(espClient);
unsigned long lastMsg = 0;
#define MSG_BUFFER_SIZE  (50)
char msg[MSG_BUFFER_SIZE];
int value = 0;

void setup_wifi() {
  delay(10);
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  randomSeed(micros());

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
}

void reconnect() {
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection...");
    String clientId = "ESP8266Client-";
    clientId += String(random(0xffff), HEX);
    if (client.connect(clientId.c_str())) {
      Serial.println("connected");
      client.publish("PMCkel18", "Pembacaan BPM siap");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" try again in 5 seconds");
      delay(5000);
    }
  }
}

//--------------------------------------------------------------------------------void GetHeartRate()
// This subroutine is for reading the heart rate and calculating it to get the BPM value.
// To get a BPM value based on a heart rate reading for 3 seconds.
void GetHeartRate() {
  //----------------------------------------Process of reading heart rate.
  unsigned long currentMillisGetHR = millis();

  if (currentMillisGetHR - previousMillisGetHR >= intervalGetHR) {
    previousMillisGetHR = currentMillisGetHR;

    int PulseSensorHRVal = analogRead(PulseSensorHRWire);

    if (PulseSensorHRVal > Threshold && ThresholdStat == true) {
      cntHB++;
      ThresholdStat = false;
      digitalWrite(LED_D6,HIGH);
    }

    if (PulseSensorHRVal < Threshold) {
      ThresholdStat = true;
      digitalWrite(LED_D6,LOW);
    }
  }
  //----------------------------------------

  //----------------------------------------The process for getting the BPM value.
  unsigned long currentMillisHR = millis();

  if (currentMillisHR - previousMillisHR >= intervalHR) {
    previousMillisHR = currentMillisHR;

    BPMval = cntHB * 20; //--> The taken heart rate is for 3 seconds. So to get the BPM value, the total heart rate in 3 seconds x 20.
    Serial.print("BPM : ");
    Serial.println(BPMval);
    
    // Pindahkan kursor ke kolom 0 dan baris 0
    // (baris 1)
    lcd.clear();
    lcd.setCursor(0, 0);
    // Cetak hellow ke layar
    lcd.print("BPM : ");
    lcd.print(BPMval);


   // Inisialisasi kunci dan nonce
    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));

    ad_len = strlen((char*) ad) - 1;
    ad[ad_len] = '\0';

    // Input plaintext
    //memcpy(&plaintext, &BPMval, MAX_MSG_LENGTH);
    String plaintext = String(BPMval);
 
    plaintext_len = strlen((char*) plaintext) - 1;
    plaintext[plaintext_len] = '\0';

    // Input additional data
    //printf("Masukkan additional data: ");
    //fgets((char*) ad, AD_BLK_LEN_EVN, stdin);


    // Enkripsi plaintext
    if (crypto_aead_encrypt(ciphertext, &ciphertext_len, plaintext, plaintext_len, ad, ad_len, NULL, nonce, key) != 0) {
        printf("Enkripsi gagal\n");
        //return 1;
    }

    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
       
    char pesan[10]; // Anggap panjang maksimum pesan adalah 4 karakter
    snprintf(pesan, sizeof(pesan), "BPM: %d", BPMval); // Mengonversi BPMval menjadi string dan menyimpannya di variabel pesan
    client.publish("PMCkel18", pesan); // Memublikasikan pesan dengan topik "PMCkel18" dan BPMval yang sudah dikonversi

    cntHB = 0;
  }
  //----------------------------------------
}
//--------------------------------------------------------------------------------



void setup() {
  Serial.begin(115200);
  setup_wifi();
  client.setServer(mqtt_server, 1883);

  // Pemanggilan pertama memerlukan parameter jumlah kolom dan baris
  // Ini harus sama dengan yang dimasukan pada konstruktor.
  lcd.begin(16,2);
  lcd.init();
 
  // Nyalakan backlight
  lcd.backlight();
  lcd.setCursor(0, 0);
   
  // Cetak hellow ke layar
  lcd.print("PMC KEL 18");
  
  pinMode(LED_D6, OUTPUT);     // Initialize the BUILTIN_LED pin as an output
}

void loop() {

  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  GetHeartRate(); // Memperbarui nilai BPMval setiap intervalGetHR
  
  // Pindahkan kursor ke baris berikutnya dan cetak lagi
  lcd.setCursor(0, 1);  

  lcd.print("Cipher : -");

}
