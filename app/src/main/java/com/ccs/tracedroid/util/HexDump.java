// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.util;

import java.util.Locale;

/** Classic 16-bytes-per-row hex dump used for YARA match previews. */
public final class HexDump {
    private HexDump() {
    }

    /** Parses a lower/upper-case hex string; invalid input yields an empty array. */
    public static byte[] parse(String hex) {
        if (hex == null || (hex.length() & 1) != 0) {
            return new byte[0];
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                return new byte[0];
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /**
     * Formats {@code data}, which starts at absolute offset {@code baseOffset}, as rows of
     * "offset  hex bytes  |ascii|". Rows are aligned to 16-byte boundaries of the artifact.
     */
    public static String format(byte[] data, long baseOffset) {
        if (data.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(data.length * 5);
        long rowStart = baseOffset & ~0xFL;
        long end = baseOffset + data.length;
        for (long row = rowStart; row < end; row += 16) {
            sb.append(String.format(Locale.ROOT, "%08x  ", row));
            StringBuilder ascii = new StringBuilder(16);
            for (int col = 0; col < 16; col++) {
                long pos = row + col;
                if (pos < baseOffset || pos >= end) {
                    sb.append("   ");
                    ascii.append(' ');
                } else {
                    int b = data[(int) (pos - baseOffset)] & 0xFF;
                    sb.append(Character.forDigit(b >> 4, 16)).append(Character.forDigit(b & 0xF, 16)).append(' ');
                    ascii.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
                }
                if (col == 7) {
                    sb.append(' ');
                }
            }
            sb.append(" |").append(ascii).append("|");
            if (row + 16 < end) {
                sb.append('\n');
            }
        }
        return sb.toString();
    }
}
