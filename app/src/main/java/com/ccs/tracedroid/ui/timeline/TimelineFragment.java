// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.timeline;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.DividerItemDecoration;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.TraceDroidApp;
import com.ccs.tracedroid.jni.NativeForensicEngine;
import com.ccs.tracedroid.model.EventRow;
import com.ccs.tracedroid.ui.cases.CaseViewModel;
import com.ccs.tracedroid.util.Formats;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Event timeline: keyword / regular-expression search, event-id and severity filters, all
 * evaluated natively; rows are paged in through direct buffers as the list scrolls.
 */
public final class TimelineFragment extends Fragment implements TimelineAdapter.Host {
    private static final long SEARCH_DEBOUNCE_MS = 300;

    private CaseViewModel viewModel;
    private TimelineAdapter adapter;
    private TextInputEditText searchInput;
    private TextInputEditText eventIdInput;
    private TextInputLayout searchLayout;
    private Chip regexChip;
    private ChipGroup severityGroup;
    private TextView resultCount;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable debouncedQuery = this::runQuery;
    /** Identifies the newest query so results of superseded ones are dropped. */
    private final AtomicInteger querySerial = new AtomicInteger();

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle state) {
        return inflater.inflate(R.layout.fragment_timeline, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        viewModel = new ViewModelProvider(requireActivity()).get(CaseViewModel.class);
        adapter = new TimelineAdapter(this);

        RecyclerView list = view.findViewById(R.id.event_list);
        list.setLayoutManager(new LinearLayoutManager(requireContext()));
        list.setAdapter(adapter);
        list.setItemAnimator(null);  // page arrivals should not animate thousands of rows
        list.addItemDecoration(new DividerItemDecoration(requireContext(), DividerItemDecoration.VERTICAL));

        searchLayout = view.findViewById(R.id.search_layout);
        searchInput = view.findViewById(R.id.search_input);
        eventIdInput = view.findViewById(R.id.event_id_input);
        regexChip = view.findViewById(R.id.chip_regex);
        severityGroup = view.findViewById(R.id.severity_group);
        resultCount = view.findViewById(R.id.result_count);

        TextWatcher watcher = new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                scheduleQuery();
            }
        };
        searchInput.addTextChangedListener(watcher);
        eventIdInput.addTextChangedListener(watcher);
        searchInput.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_SEARCH) {
                handler.removeCallbacks(debouncedQuery);
                runQuery();
                return true;
            }
            return false;
        });
        regexChip.setOnCheckedChangeListener((button, checked) -> scheduleQuery());
        severityGroup.setOnCheckedStateChangeListener((group, checkedIds) -> scheduleQuery());

        // Re-run the current filter whenever events or alerts change underneath us.
        viewModel.dataVersion().observe(getViewLifecycleOwner(), version -> runQuery());
    }

    @Override
    public void onDestroyView() {
        handler.removeCallbacks(debouncedQuery);
        querySerial.incrementAndGet();
        super.onDestroyView();
    }

    private void scheduleQuery() {
        handler.removeCallbacks(debouncedQuery);
        handler.postDelayed(debouncedQuery, SEARCH_DEBOUNCE_MS);
    }

    private int selectedSeverity() {
        int id = severityGroup.getCheckedChipId();
        if (id == R.id.chip_sev_low) {
            return 2;
        }
        if (id == R.id.chip_sev_medium) {
            return 3;
        }
        if (id == R.id.chip_sev_high) {
            return 4;
        }
        if (id == R.id.chip_sev_critical) {
            return 5;
        }
        if (id == R.id.chip_sev_any_alert) {
            return 1;
        }
        return 0;
    }

    private static String text(TextInputEditText input) {
        return input.getText() == null ? "" : input.getText().toString();
    }

    private void runQuery() {
        final NativeForensicEngine engine = viewModel.engine();
        if (engine == null || getView() == null) {
            return;
        }
        final String text = text(searchInput).trim();
        final boolean regex = regexChip.isChecked();
        final int minSeverity = selectedSeverity();
        int parsedId = -1;
        try {
            String idText = text(eventIdInput).trim();
            if (!idText.isEmpty()) {
                parsedId = Integer.parseInt(idText);
            }
        } catch (NumberFormatException ignored) {
            parsedId = -1;
        }
        final int eventId = parsedId;
        final int serial = querySerial.incrementAndGet();
        final TraceDroidApp app = TraceDroidApp.from(requireContext());

        app.io().execute(() -> {
            int total;
            String error = null;
            try {
                // The query and its first page are produced back to back so the list never
                // shows rows from a different result set than the count.
                total = engine.query(text, regex, eventId, minSeverity, Long.MIN_VALUE, Long.MAX_VALUE);
            } catch (RuntimeException e) {
                total = 0;
                error = e.getMessage();
            }
            final int count = total;
            final String message = error;
            app.postMain(() -> {
                if (serial != querySerial.get() || getView() == null) {
                    return;
                }
                searchLayout.setError(message);
                adapter.reset(count);
                resultCount.setText(getString(R.string.result_count, Formats.count(count)));
            });
        });
    }

    @Override
    public void requestPage(int generation, int page) {
        final NativeForensicEngine engine = viewModel.engine();
        if (engine == null) {
            return;
        }
        final TraceDroidApp app = TraceDroidApp.from(requireContext());
        app.io().execute(() -> {
            try {
                List<EventRow> rows = engine.fetchPage(page * TimelineAdapter.PAGE_SIZE, TimelineAdapter.PAGE_SIZE);
                app.postMain(() -> adapter.onPageLoaded(generation, page, rows));
            } catch (RuntimeException e) {
                app.postMain(() -> adapter.onPageFailed(generation, page));
            }
        });
    }

    @Override
    public void onRowClicked(EventRow row) {
        EventDetailSheet.show(getParentFragmentManager(), row.eventIndex);
    }
}
