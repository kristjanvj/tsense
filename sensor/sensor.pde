void setup()
{
  Serial.begin(9600);
  delay(10000);
  Serial.print("ID 0000:0001\n");
  
  // Dirty hack; wait a few ms
  delay(200);
  // Wait for challenge from computer
  if (Serial.available() > 0)
  {
    if (Serial.read() == 'C')
    {
      Serial.print("I'm ready for the challenge!\n");
    }
    else
    {
      Serial.print("Nope.");
    }
  }
}

void loop()
{
  //
}

