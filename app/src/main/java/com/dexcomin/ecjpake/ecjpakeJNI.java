/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.1
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package com.dexcomin.ecjpake;

public class ecjpakeJNI {
  public final static native byte[] writeRoundOneJ(int Round_Number);
  public final static native byte[] writeRoundTwoJ();
  public final static native byte[] getKey();
  public final static native int readRoundOneJ(byte[] jarg1,int size, int Round_Number);
  public final static native void readRoundTwoJ(byte[] jarg1);
  public final static native void setInfo(byte[] jarg1);
  public final static native byte[] sayHello();
  public final static native void init();
}
