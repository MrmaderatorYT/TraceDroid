// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.timeline;

import android.util.LruCache;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.model.EventRow;
import com.ccs.tracedroid.util.Formats;
import com.ccs.tracedroid.util.Severity;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Virtualised timeline adapter. The item count is the size of the native result set (possibly
 * millions); rows are materialised page by page on demand and only a bounded window of pages is
 * kept on the Java heap. Everything here runs on the main thread.
 */
final class TimelineAdapter extends RecyclerView.Adapter<TimelineAdapter.Holder> {
    static final int PAGE_SIZE = 200;
    private static final int MAX_CACHED_PAGES = 24;

    interface Host {
        /** Load page {@code page} in the background and answer with {@link #onPageLoaded}. */
        void requestPage(int generation, int page);

        void onRowClicked(EventRow row);
    }

    private final Host host;
    private final LruCache<Integer, List<EventRow>> pages = new LruCache<>(MAX_CACHED_PAGES);
    private final Set<Integer> loading = new HashSet<>();
    private int total;
    private int generation;

    TimelineAdapter(Host host) {
        this.host = host;
    }

    /** Starts a new result set; pages of older generations still in flight are ignored when they arrive. */
    void reset(int newTotal) {
        generation++;
        pages.evictAll();
        loading.clear();
        total = newTotal;
        notifyDataSetChanged();
    }

    int generation() {
        return generation;
    }

    void onPageLoaded(int forGeneration, int page, List<EventRow> rows) {
        if (forGeneration != generation) {
            return;
        }
        loading.remove(page);
        pages.put(page, rows);
        notifyItemRangeChanged(page * PAGE_SIZE, rows.size());
    }

    void onPageFailed(int forGeneration, int page) {
        if (forGeneration == generation) {
            loading.remove(page);
        }
    }

    private EventRow rowAt(int position) {
        int page = position / PAGE_SIZE;
        List<EventRow> rows = pages.get(page);
        if (rows == null) {
            if (loading.add(page)) {
                host.requestPage(generation, page);
            }
            return null;
        }
        int offset = position - page * PAGE_SIZE;
        return offset < rows.size() ? rows.get(offset) : null;
    }

    @Override
    public int getItemCount() {
        return total;
    }

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        return new Holder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_event, parent, false));
    }

    @Override
    public void onBindViewHolder(@NonNull Holder holder, int position) {
        EventRow row = rowAt(position);
        holder.bind(row);
        holder.itemView.setOnClickListener(row == null ? null : v -> host.onRowClicked(row));
    }

    static final class Holder extends RecyclerView.ViewHolder {
        private final View badge;
        private final TextView time;
        private final TextView eventId;
        private final TextView title;
        private final TextView summary;
        private final TextView host;
        private final TextView severity;

        Holder(View view) {
            super(view);
            badge = view.findViewById(R.id.severity_bar);
            time = view.findViewById(R.id.event_time);
            eventId = view.findViewById(R.id.event_id);
            title = view.findViewById(R.id.event_title);
            summary = view.findViewById(R.id.event_summary);
            host = view.findViewById(R.id.event_host);
            severity = view.findViewById(R.id.event_severity);
        }

        void bind(EventRow row) {
            if (row == null) {
                // Placeholder while the page is being fetched from the native index.
                badge.setBackgroundColor(Severity.color(itemView.getContext(), Severity.NONE));
                time.setText("…");
                eventId.setText("");
                title.setText("");
                summary.setText("");
                host.setText("");
                severity.setVisibility(View.GONE);
                return;
            }
            int color = Severity.color(itemView.getContext(), row.severity);
            badge.setBackgroundColor(color);
            time.setText(Formats.utc(row.timeMs));
            eventId.setText(String.format(Locale.ROOT, "%d", row.eventId));
            title.setText(row.title);
            summary.setText(row.summary);
            host.setText(row.computer);
            if (row.severity > 0) {
                severity.setVisibility(View.VISIBLE);
                String name = Severity.name(itemView.getContext(), row.severity).toUpperCase(Locale.ROOT);
                severity.setText(row.alertCount > 1 ? name + " ×" + row.alertCount : name);
                severity.getBackground().mutate().setTint(color);
            } else {
                severity.setVisibility(View.GONE);
            }
        }
    }
}
