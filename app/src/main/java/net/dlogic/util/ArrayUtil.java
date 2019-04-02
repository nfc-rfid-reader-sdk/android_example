package net.dlogic.util;

public class ArrayUtil {
    public static Byte[] bytesToObjects(byte[] bPrim) {
        Byte[] bObj = new Byte[bPrim.length];
        for (int i = 0; i < bPrim.length; i++) {
            bObj[i] = Byte.valueOf(bPrim[i]);
        }
        return bObj;
    }

    public static byte[] bytesFromObjects(Byte[] bObj) {
        byte[] bPrim = new byte[bObj.length];
        for (int i = 0; i < bObj.length; i++)
        {
            bPrim[i] = bObj[i];
        }
        return bPrim;
    }

    public static String bytesToHex(byte[] byteArray) {
        StringBuilder sBuilder = new StringBuilder(byteArray.length * 2);
        for(byte b: byteArray)
            sBuilder.append(String.format("%02x", b & 0xff));
        return sBuilder.toString();
    }
}
