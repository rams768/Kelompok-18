int Pulse = 0;
int LED = 13;
int Signal;
int Threshold = 550;

void setup() {
  pinMode(LED, OUTPUT);
  Serial.begin(9600); 
}

void loop() {
  Signal = analogRead(Pulse);
  Serial.println(Signal);

  if(Signal > Threshold){
    digitalWrite(LED, HIGH);
    delay(1000);
  }else{
    digitalWrite(LED, LOW);
    delay(1000);
  }
}
