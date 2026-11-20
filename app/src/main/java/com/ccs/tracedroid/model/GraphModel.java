// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.model;

import androidx.annotation.NonNull;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Immutable process / network graph with native-computed coordinates, decoded from the geometry
 * buffer produced by GraphLayoutEngine::serialize. Stored as flat primitive arrays so the view
 * can cull and draw tens of thousands of nodes without allocating.
 */
public final class GraphModel {
    public static final int TYPE_PROCESS = 0;
    public static final int TYPE_NETWORK = 1;
    public static final int TYPE_DNS = 2;

    public static final int FLAG_SYNTHETIC = 1;
    public static final int FLAG_TERMINATED = 2;
    public static final int FLAG_ROOT = 4;

    private static final int MAGIC = 0x31474454; // "TDG1"

    public final int nodeCount;
    public final int edgeCount;
    public final boolean truncated;
    public final boolean forceLayout;
    public final float minX;
    public final float minY;
    public final float maxX;
    public final float maxY;
    public final float[] x;
    public final float[] y;
    public final byte[] type;
    public final byte[] severity;
    public final short[] flags;
    public final int[] parent;
    /** Edge list as (source, target) node index pairs. */
    public final int[] edges;
    public final String[] labels;

    private GraphModel(ByteBuffer in) {
        if (in.remaining() < 32 || in.getInt() != MAGIC) {
            throw new IllegalArgumentException("not a TraceDroid graph buffer");
        }
        nodeCount = in.getInt();
        edgeCount = in.getInt();
        int header = in.getInt();
        truncated = (header & 1) != 0;
        forceLayout = (header & 2) != 0;
        minX = in.getFloat();
        minY = in.getFloat();
        maxX = in.getFloat();
        maxY = in.getFloat();
        x = new float[nodeCount];
        y = new float[nodeCount];
        type = new byte[nodeCount];
        severity = new byte[nodeCount];
        flags = new short[nodeCount];
        parent = new int[nodeCount];
        for (int i = 0; i < nodeCount; i++) {
            x[i] = in.getFloat();
            y[i] = in.getFloat();
            type[i] = in.get();
            severity[i] = in.get();
            flags[i] = in.getShort();
            parent[i] = in.getInt();
        }
        edges = new int[edgeCount * 2];
        for (int i = 0; i < edges.length; i++) {
            edges[i] = in.getInt();
        }
        labels = new String[nodeCount];
        for (int i = 0; i < nodeCount; i++) {
            int length = in.getShort() & 0xFFFF;
            byte[] bytes = new byte[length];
            in.get(bytes);
            labels[i] = new String(bytes, StandardCharsets.UTF_8);
        }
    }

    /** Copies everything out of {@code in}; the buffer may be invalidated afterwards. */
    @NonNull
    public static GraphModel decode(@NonNull ByteBuffer in) {
        return new GraphModel(in);
    }

    public boolean isEmpty() {
        return nodeCount == 0;
    }
}
