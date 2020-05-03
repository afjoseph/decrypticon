package com.afjoseph.test;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import java.lang.Thread;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

public class MainActivity extends AppCompatActivity {
  private static final String TAG = "MainActivity";

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    try {
      Thread.sleep(4000);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
    Map<String, String> params = new HashMap<>();
    String address_1 = Cryptor.get(30, 20, 100);
    String enc_address_1 = Encryptor.Encrypt(address_1);
    params.put("address_1", enc_address_1);

    String country_1 = Cryptor.get(100, 200, 300);
    String enc_country_1 = Encryptor.Encrypt(address_1);
    params.put("country_1", enc_country_1);

    String token_1 = Cryptor.get(99, 66, 99);
    String enc_token_1 = Encryptor.Encrypt(token_1);
    params.put("token_1", enc_token_1);

    String address_2 = Cryptor.get(55, 22, 32);
    String enc_address_2 = Encryptor.Encrypt(address_2);
    params.put("address_2", enc_address_2);

    String country_2 = Cryptor.get(92, 22, 55);
    String enc_country_2 = Encryptor.Encrypt(address_2);
    params.put("country_2", enc_country_2);

    String token_2 = Cryptor.get(88, 72, 86);
    String enc_token_2 = Encryptor.Encrypt(token_2);
    params.put("token_2", enc_token_2);

    sendRequest(params);
  }

  private void sendRequest(Map<String, String> params) {
    Log.d(TAG, "sendRequest: Sending request: " + params.toString());
  }
}
