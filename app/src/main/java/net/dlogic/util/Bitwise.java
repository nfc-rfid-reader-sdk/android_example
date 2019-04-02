package net.dlogic.util;

import java.nio.ByteOrder;

public class Bitwise {
    public static short bytesToShort(byte[] abyte) {

        if (ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN))
            return (short) (abyte[0] << 8 | (abyte[1] & 0xFF));
        else
            return (short) (abyte[1] << 8 | (abyte[0] & 0xFF));
    }

    // Forced big-endian:
    public static short bytesToShortBE(byte[] abyte) {
        return (short) (abyte[0] << 8 | (abyte[1] & 0xFF));
    }

    // Forced little-endian:
    public static short bytesToShortLE(byte[] abyte) {
        return (short) (abyte[1] << 8 | (abyte[0] & 0xFF));
    }

    public static short bytesToInt(byte[] abyte) {

        if (ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN))
            return (short) (abyte[0] << 24 | abyte[1] << 16 | abyte[2] << 8 | (abyte[3] & 0xFF));
        else
            return (short) (abyte[3] << 24 | abyte[2] << 16 | abyte[1] << 8 | (abyte[0] & 0xFF));
    }

    public static short bytesToIntBE(byte[] abyte) {
        return (short) (abyte[0] << 24 | abyte[1] << 16 | abyte[2] << 8 | (abyte[3] & 0xFF));
    }

    public static short bytesToIntLE(byte[] abyte) {
        return (short) (abyte[3] << 24 | abyte[2] << 16 | abyte[1] << 8 | (abyte[0] & 0xFF));
    }
}
