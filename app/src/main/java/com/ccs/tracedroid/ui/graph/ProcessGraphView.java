// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.graph;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.View;
import android.widget.OverScroller;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.graphics.ColorUtils;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.model.GraphModel;
import com.ccs.tracedroid.util.Severity;
import com.google.android.material.color.MaterialColors;

/**
 * Hardware-accelerated interactive view of the process / network graph.
 *
 * <p>Node coordinates come from the native layout engine (world units); this view only applies
 * a pan/zoom transform, culls to the viewport and draws. Drawing allocates nothing per frame:
 * edges are batched into one reusable float array and nodes are read from the model's flat
 * primitive arrays, which keeps panning smooth with tens of thousands of nodes.
 */
public final class ProcessGraphView extends View {

    public interface OnNodeSelectedListener {
        void onNodeSelected(int nodeIndex);
    }

    // World-space metrics; must agree with the spacing used by the native layout engine.
    private static final float BOX_WIDTH = 236f;
    private static final float BOX_HEIGHT = 40f;
    private static final float PILL_HEIGHT = 30f;
    private static final float STRIPE_WIDTH = 6f;
    private static final float ELBOW = 32f;
    private static final float RADIUS_PROCESS = 15f;
    private static final float RADIUS_ACTIVITY = 9f;

    private static final float MIN_SCALE = 0.02f;
    private static final float MAX_SCALE = 3.5f;
    /** Below this zoom, labels are illegible and nodes are drawn as plain blocks. */
    private static final float DETAIL_SCALE = 0.42f;

    private final Paint fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint strokePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint edgePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint pathPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint hintPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final DashPathEffect dashed = new DashPathEffect(new float[]{8f, 6f}, 0f);
    private final RectF rect = new RectF();
    private final float[] edgeBatch = new float[4 * 3 * 512];
    private final float[] pathBatch = new float[4 * 3 * 128];

    private final int[] severityColors;
    private final int colorSurface;
    private final int colorOnSurface;
    private final int colorOutline;
    private final int colorNetwork;
    private final int colorDns;
    private final int colorAccent;

    private final ScaleGestureDetector scaleDetector;
    private final GestureDetector gestureDetector;
    private final OverScroller scroller;

    @Nullable
    private GraphModel model;
    /** Per node: true when it lies on the ancestor chain of the selected node. */
    private boolean[] onSelectedPath = new boolean[0];
    private String[] ellipsized = new String[0];
    private int selected = -1;
    private float scale = 1f;
    private float translateX;
    private float translateY;
    private boolean pendingFit;
    @Nullable
    private OnNodeSelectedListener listener;
    private String emptyHint = "";

    public ProcessGraphView(Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        severityColors = Severity.palette(context);
        colorSurface = MaterialColors.getColor(this, com.google.android.material.R.attr.colorSurfaceContainerHigh);
        colorOnSurface = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSurface);
        colorOutline = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOutline);
        colorAccent = MaterialColors.getColor(this, com.google.android.material.R.attr.colorPrimary);
        colorNetwork = context.getColor(R.color.node_network);
        colorDns = context.getColor(R.color.node_dns);

        fillPaint.setStyle(Paint.Style.FILL);
        strokePaint.setStyle(Paint.Style.STROKE);
        edgePaint.setStyle(Paint.Style.STROKE);
        edgePaint.setColor(ColorUtils.setAlphaComponent(colorOutline, 0xB0));
        pathPaint.setStyle(Paint.Style.STROKE);
        pathPaint.setColor(colorAccent);
        textPaint.setColor(colorOnSurface);
        textPaint.setTextSize(15f);
        textPaint.setTypeface(Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL));
        hintPaint.setColor(ColorUtils.setAlphaComponent(colorOnSurface, 0xA0));
        hintPaint.setTextAlign(Paint.Align.CENTER);
        hintPaint.setTextSize(android.util.TypedValue.applyDimension(android.util.TypedValue.COMPLEX_UNIT_SP, 15f, getResources().getDisplayMetrics()));

        scroller = new OverScroller(context);
        scaleDetector = new ScaleGestureDetector(context, new ScaleGestureDetector.SimpleOnScaleGestureListener() {
            @Override
            public boolean onScale(@NonNull ScaleGestureDetector detector) {
                zoomAround(detector.getFocusX(), detector.getFocusY(), detector.getScaleFactor());
                return true;
            }
        });
        gestureDetector = new GestureDetector(context, new GestureDetector.SimpleOnGestureListener() {
            @Override
            public boolean onDown(@NonNull MotionEvent e) {
                scroller.forceFinished(true);
                return true;
            }

            @Override
            public boolean onScroll(@Nullable MotionEvent e1, @NonNull MotionEvent e2, float dx, float dy) {
                translateX -= dx;
                translateY -= dy;
                postInvalidateOnAnimation();
                return true;
            }

            @Override
            public boolean onFling(@Nullable MotionEvent e1, @NonNull MotionEvent e2, float vx, float vy) {
                scroller.fling((int) translateX, (int) translateY, (int) vx, (int) vy,
                        Integer.MIN_VALUE, Integer.MAX_VALUE, Integer.MIN_VALUE, Integer.MAX_VALUE);
                postInvalidateOnAnimation();
                return true;
            }

            @Override
            public boolean onSingleTapUp(@NonNull MotionEvent e) {
                int hit = nodeAt(e.getX(), e.getY());
                select(hit);
                if (hit >= 0 && listener != null) {
                    listener.onNodeSelected(hit);
                }
                return true;
            }

            @Override
            public boolean onDoubleTap(@NonNull MotionEvent e) {
                zoomAround(e.getX(), e.getY(), 1.7f);
                return true;
            }
        });
        setFocusable(true);
    }

    public void setOnNodeSelectedListener(@Nullable OnNodeSelectedListener l) {
        listener = l;
    }

    public void setEmptyHint(String hint) {
        emptyHint = hint == null ? "" : hint;
        invalidate();
    }

    /** Replaces the graph. The viewport is re-fitted because node indices and positions changed. */
    public void setModel(@Nullable GraphModel newModel) {
        model = newModel;
        selected = -1;
        int n = newModel == null ? 0 : newModel.nodeCount;
        onSelectedPath = new boolean[n];
        ellipsized = new String[n];
        scroller.forceFinished(true);
        if (getWidth() > 0 && getHeight() > 0) {
            resetViewport();
        } else {
            pendingFit = true;
        }
        invalidate();
    }

    /** Small graphs are fitted entirely; large ones open at a readable zoom on the first (most severe) tree. */
    public void resetViewport() {
        GraphModel m = model;
        if (m == null || m.isEmpty()) {
            return;
        }
        if (m.nodeCount <= 120) {
            fitToContent();
        } else {
            scale = 0.8f;
            translateX = getWidth() * 0.12f - m.x[0] * scale;
            translateY = getHeight() * 0.5f - m.y[0] * scale;
            invalidate();
        }
    }

    public void fitToContent() {
        GraphModel m = model;
        if (m == null || m.isEmpty() || getWidth() == 0) {
            return;
        }
        float pad = BOX_WIDTH * 0.6f;
        float left = m.minX - pad;
        float top = m.minY - pad;
        float width = (m.maxX - m.minX) + BOX_WIDTH + 2 * pad;
        float height = (m.maxY - m.minY) + 2 * pad;
        scale = clampScale(Math.min(getWidth() / width, getHeight() / height));
        scale = Math.min(scale, 1.3f);
        translateX = (getWidth() - width * scale) / 2f - left * scale;
        translateY = (getHeight() - height * scale) / 2f - top * scale;
        invalidate();
    }

    public void centerOn(int node) {
        GraphModel m = model;
        if (m == null || node < 0 || node >= m.nodeCount) {
            return;
        }
        if (scale < 0.6f) {
            scale = 0.9f;
        }
        translateX = getWidth() / 2f - (m.x[node] + (m.forceLayout ? 0 : BOX_WIDTH / 2f)) * scale;
        translateY = getHeight() / 2f - m.y[node] * scale;
        invalidate();
    }

    public void select(int node) {
        GraphModel m = model;
        selected = node;
        if (m != null) {
            java.util.Arrays.fill(onSelectedPath, false);
            for (int cur = node, hops = 0; cur >= 0 && cur < m.nodeCount && hops < 4096; cur = m.parent[cur], hops++) {
                onSelectedPath[cur] = true;
            }
        }
        invalidate();
    }

    public int selected() {
        return selected;
    }

    private static float clampScale(float s) {
        return Math.max(MIN_SCALE, Math.min(MAX_SCALE, s));
    }

    private void zoomAround(float focusX, float focusY, float factor) {
        float newScale = clampScale(scale * factor);
        float applied = newScale / scale;
        // Keep the world point under the focus stationary on screen.
        translateX = focusX - (focusX - translateX) * applied;
        translateY = focusY - (focusY - translateY) * applied;
        scale = newScale;
        postInvalidateOnAnimation();
    }

    @Override
    protected void onSizeChanged(int w, int h, int oldW, int oldH) {
        super.onSizeChanged(w, h, oldW, oldH);
        if (pendingFit && w > 0 && h > 0) {
            pendingFit = false;
            resetViewport();
        }
    }

    @Override
    public void computeScroll() {
        if (scroller.computeScrollOffset()) {
            translateX = scroller.getCurrX();
            translateY = scroller.getCurrY();
            postInvalidateOnAnimation();
        }
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        getParent().requestDisallowInterceptTouchEvent(true);
        boolean handled = scaleDetector.onTouchEvent(event);
        if (!scaleDetector.isInProgress()) {
            handled |= gestureDetector.onTouchEvent(event);
        }
        if (event.getActionMasked() == MotionEvent.ACTION_UP) {
            performClick();
        }
        return handled || super.onTouchEvent(event);
    }

    @Override
    public boolean performClick() {
        return super.performClick();
    }

    // ---- geometry helpers (world space) ----

    private static float nodeWidth(GraphModel m, int i) {
        if (m.forceLayout) {
            return 0f;
        }
        return BOX_WIDTH;
    }

    private static float nodeHalfHeight(GraphModel m, int i) {
        if (m.forceLayout) {
            return m.type[i] == GraphModel.TYPE_PROCESS ? RADIUS_PROCESS : RADIUS_ACTIVITY;
        }
        return (m.type[i] == GraphModel.TYPE_PROCESS ? BOX_HEIGHT : PILL_HEIGHT) / 2f;
    }

    private int nodeAt(float screenX, float screenY) {
        GraphModel m = model;
        if (m == null) {
            return -1;
        }
        float wx = (screenX - translateX) / scale;
        float wy = (screenY - translateY) / scale;
        float slop = 14f * getResources().getDisplayMetrics().density / scale;
        int best = -1;
        float bestDistance = Float.MAX_VALUE;
        for (int i = 0; i < m.nodeCount; i++) {
            float half = nodeHalfHeight(m, i);
            float dx;
            float dy = Math.max(0f, Math.abs(wy - m.y[i]) - half);
            if (m.forceLayout) {
                dx = Math.max(0f, Math.abs(wx - m.x[i]) - half);
            } else {
                dx = wx < m.x[i] ? m.x[i] - wx : Math.max(0f, wx - (m.x[i] + BOX_WIDTH));
            }
            float distance = dx * dx + dy * dy;
            if (distance < bestDistance) {
                bestDistance = distance;
                best = i;
            }
        }
        return bestDistance <= slop * slop ? best : -1;
    }

    private int nodeColor(GraphModel m, int i) {
        int severity = m.severity[i] & 0xFF;
        if (severity > 0) {
            return severityColors[Math.min(severity, severityColors.length - 1)];
        }
        switch (m.type[i]) {
            case GraphModel.TYPE_NETWORK:
                return colorNetwork;
            case GraphModel.TYPE_DNS:
                return colorDns;
            default:
                return colorOutline;
        }
    }

    private String label(GraphModel m, int i, float maxWidth) {
        String cached = ellipsized[i];
        if (cached == null) {
            // Text metrics are in world units, so the result is independent of the zoom level.
            cached = TextUtils.ellipsize(m.labels[i], new android.text.TextPaint(textPaint), maxWidth,
                    TextUtils.TruncateAt.MIDDLE).toString();
            ellipsized[i] = cached;
        }
        return cached;
    }

    // ---- drawing ----

    @Override
    protected void onDraw(@NonNull Canvas canvas) {
        GraphModel m = model;
        if (m == null || m.isEmpty()) {
            canvas.drawText(emptyHint, getWidth() / 2f, getHeight() / 2f, hintPaint);
            return;
        }

        // Visible world rectangle, grown by one node so partially visible nodes are kept.
        final float left = -translateX / scale - BOX_WIDTH;
        final float top = -translateY / scale - BOX_HEIGHT;
        final float right = (getWidth() - translateX) / scale + BOX_WIDTH;
        final float bottom = (getHeight() - translateY) / scale + BOX_HEIGHT;

        canvas.save();
        canvas.translate(translateX, translateY);
        canvas.scale(scale, scale);

        // Constant on-screen line widths regardless of zoom.
        final float density = getResources().getDisplayMetrics().density;
        edgePaint.setStrokeWidth(1.1f * density / scale);
        pathPaint.setStrokeWidth(2.6f * density / scale);

        drawEdges(canvas, m, left, top, right, bottom);
        final boolean detailed = scale >= DETAIL_SCALE;
        for (int i = 0; i < m.nodeCount; i++) {
            final float x = m.x[i];
            final float y = m.y[i];
            if (x > right || x + BOX_WIDTH < left || y - BOX_HEIGHT > bottom || y + BOX_HEIGHT < top) {
                continue;
            }
            if (m.forceLayout) {
                drawForceNode(canvas, m, i, detailed, density);
            } else {
                drawTreeNode(canvas, m, i, detailed, density);
            }
        }
        canvas.restore();
    }

    private void drawEdges(Canvas canvas, GraphModel m, float left, float top, float right, float bottom) {
        int count = 0;
        int pathCount = 0;
        final int[] edges = m.edges;
        for (int e = 0; e < edges.length; e += 2) {
            final int s = edges[e];
            final int t = edges[e + 1];
            final float sx = m.x[s] + nodeWidth(m, s);
            final float sy = m.y[s];
            final float tx = m.x[t];
            final float ty = m.y[t];
            if (Math.max(sx, tx) < left || Math.min(sx, tx) > right || Math.max(sy, ty) < top || Math.min(sy, ty) > bottom) {
                continue;
            }
            // An edge is on the highlighted path when its child end is an ancestor-or-self of the selection.
            final boolean highlight = selected >= 0 && onSelectedPath[t];
            final float[] batch = highlight ? pathBatch : edgeBatch;
            int at = highlight ? pathCount : count;
            if (at + 12 > batch.length) {
                canvas.drawLines(batch, 0, at, highlight ? pathPaint : edgePaint);
                at = 0;
            }
            if (m.forceLayout) {
                batch[at++] = sx;
                batch[at++] = sy;
                batch[at++] = tx;
                batch[at++] = ty;
            } else {
                // Orthogonal connector: out of the parent, down/up the gutter, into the child.
                final float mx = tx - ELBOW;
                batch[at++] = sx;
                batch[at++] = sy;
                batch[at++] = mx;
                batch[at++] = sy;
                batch[at++] = mx;
                batch[at++] = sy;
                batch[at++] = mx;
                batch[at++] = ty;
                batch[at++] = mx;
                batch[at++] = ty;
                batch[at++] = tx;
                batch[at++] = ty;
            }
            if (highlight) {
                pathCount = at;
            } else {
                count = at;
            }
        }
        if (count > 0) {
            canvas.drawLines(edgeBatch, 0, count, edgePaint);
        }
        if (pathCount > 0) {
            canvas.drawLines(pathBatch, 0, pathCount, pathPaint);
        }
    }

    private void drawTreeNode(Canvas canvas, GraphModel m, int i, boolean detailed, float density) {
        final boolean process = m.type[i] == GraphModel.TYPE_PROCESS;
        final float half = nodeHalfHeight(m, i);
        final int color = nodeColor(m, i);
        final int severity = m.severity[i] & 0xFF;
        rect.set(m.x[i], m.y[i] - half, m.x[i] + BOX_WIDTH, m.y[i] + half);
        final float corner = process ? 8f : half;

        if (!detailed) {
            fillPaint.setColor(severity > 0 || !process ? color : ColorUtils.setAlphaComponent(colorOutline, 0x90));
            canvas.drawRoundRect(rect, corner, corner, fillPaint);
            if (i == selected) {
                strokePaint.setColor(colorAccent);
                strokePaint.setPathEffect(null);
                strokePaint.setStrokeWidth(3f * density / scale);
                canvas.drawRoundRect(rect, corner, corner, strokePaint);
            }
            return;
        }

        fillPaint.setColor(severity > 0 ? ColorUtils.blendARGB(colorSurface, color, 0.22f) : colorSurface);
        canvas.drawRoundRect(rect, corner, corner, fillPaint);

        // Severity stripe on the leading edge.
        fillPaint.setColor(color);
        canvas.save();
        canvas.clipRect(rect.left, rect.top, rect.left + STRIPE_WIDTH, rect.bottom);
        canvas.drawRoundRect(rect, corner, corner, fillPaint);
        canvas.restore();

        final boolean synthetic = (m.flags[i] & GraphModel.FLAG_SYNTHETIC) != 0;
        strokePaint.setColor(i == selected ? colorAccent : color);
        strokePaint.setStrokeWidth((i == selected ? 2.8f : 1.2f) * density / scale);
        strokePaint.setPathEffect(synthetic && i != selected ? dashed : null);
        canvas.drawRoundRect(rect, corner, corner, strokePaint);

        textPaint.setTextSize(process ? 15f : 13f);
        textPaint.setFakeBoldText(severity >= 4);
        textPaint.setAlpha(synthetic ? 0xA0 : 0xFF);
        final float textLeft = rect.left + STRIPE_WIDTH + 8f;
        final String text = label(m, i, BOX_WIDTH - STRIPE_WIDTH - 16f);
        canvas.drawText(text, textLeft, m.y[i] - (textPaint.ascent() + textPaint.descent()) / 2f, textPaint);
    }

    private void drawForceNode(Canvas canvas, GraphModel m, int i, boolean detailed, float density) {
        final boolean process = m.type[i] == GraphModel.TYPE_PROCESS;
        final float radius = process ? RADIUS_PROCESS : RADIUS_ACTIVITY;
        final int color = nodeColor(m, i);
        final int severity = m.severity[i] & 0xFF;
        final boolean synthetic = (m.flags[i] & GraphModel.FLAG_SYNTHETIC) != 0;

        fillPaint.setColor(severity > 0 || !process ? color : colorSurface);
        if (process) {
            canvas.drawCircle(m.x[i], m.y[i], radius, fillPaint);
        } else {
            rect.set(m.x[i] - radius, m.y[i] - radius, m.x[i] + radius, m.y[i] + radius);
            canvas.drawRoundRect(rect, 3f, 3f, fillPaint);
        }
        strokePaint.setColor(i == selected ? colorAccent : color);
        strokePaint.setStrokeWidth((i == selected ? 3f : 1.4f) * density / scale);
        strokePaint.setPathEffect(synthetic && i != selected ? dashed : null);
        canvas.drawCircle(m.x[i], m.y[i], radius + (i == selected ? 4f : 0f), strokePaint);

        if (detailed) {
            textPaint.setTextSize(process ? 14f : 12f);
            textPaint.setFakeBoldText(severity >= 4);
            textPaint.setAlpha(synthetic ? 0xA0 : 0xFF);
            canvas.drawText(label(m, i, BOX_WIDTH), m.x[i] + radius + 6f,
                    m.y[i] - (textPaint.ascent() + textPaint.descent()) / 2f, textPaint);
        }
    }
}
