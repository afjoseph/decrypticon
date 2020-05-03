package com.afjoseph.test;

public class Cryptor {
  private static String[] stuff = {"neverwhere", "usa", "12341234", "baldurs_gate", "temeria", "abcdabcd"};
  private static int counter = 0;
    public static String get(int a, int b, int c) {
      String retval = stuff[counter++];
      if (counter >= stuff.length) {
        counter = 0;
      }

      return retval;
    }
}
