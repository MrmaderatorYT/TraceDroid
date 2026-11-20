// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.graph;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.TraceDroidApp;
import com.ccs.tracedroid.jni.NativeForensicEngine;
import com.ccs.tracedroid.model.GraphModel;
import com.ccs.tracedroid.ui.cases.CaseViewModel;
import com.ccs.tracedroid.util.Formats;
import com.google.android.material.button.MaterialButtonToggleGroup;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.progressindicator.CircularProgressIndicator;

import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Process execution tree with attached network connections and DNS queries. The graph is
 * reconstructed and laid out natively; this screen only chooses the options and hosts the view.
 */
public final class GraphFragment extends Fragment {
    private static final int MAX_NODES = 20000;

    private CaseViewModel viewModel;
    private ProcessGraphView graphView;
    private TextView summary;
    private CircularProgressIndicator spinner;
    private MaterialButtonToggleGroup layoutToggle;
    private ChipGroup severityGroup;
    private Chip networkChip;
    private Chip dnsChip;
    private final AtomicInteger buildSerial = new AtomicInteger();
    /** Set while hidden so the (possibly expensive) rebuild is deferred until the tab is shown. */
    private boolean dirty = true;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle state) {
        return inflater.inflate(R.layout.fragment_graph, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        viewModel = new ViewModelProvider(requireActivity()).get(CaseViewModel.class);
        graphView = view.findViewById(R.id.graph_view);
        summary = view.findViewById(R.id.graph_summary);
        spinner = view.findViewById(R.id.graph_spinner);
        layoutToggle = view.findViewById(R.id.layout_toggle);
        severityGroup = view.findViewById(R.id.graph_severity_group);
        networkChip = view.findViewById(R.id.chip_network);
        dnsChip = view.findViewById(R.id.chip_dns);

        graphView.setEmptyHint(getString(R.string.graph_empty));
        graphView.setOnNodeSelectedListener(node -> NodeInspectorSheet.show(getParentFragmentManager(), node));
        view.findViewById(R.id.btn_fit).setOnClickListener(v -> graphView.fitToContent());

        layoutToggle.addOnButtonCheckedListener((group, checkedId, isChecked) -> {
            if (isChecked) {
                rebuild();
            }
        });
        severityGroup.setOnCheckedStateChangeListener((group, ids) -> rebuild());
        networkChip.setOnCheckedChangeListener((button, checked) -> rebuild());
        dnsChip.setOnCheckedChangeListener((button, checked) -> rebuild());

        viewModel.dataVersion().observe(getViewLifecycleOwner(), version -> {
            dirty = true;
            if (!isHidden()) {
                rebuild();
            }
        });
    }

    @Override
    public void onHiddenChanged(boolean hidden) {
        super.onHiddenChanged(hidden);
        if (!hidden && dirty) {
            rebuild();
        }
    }

    @Override
    public void onDestroyView() {
        buildSerial.incrementAndGet();
        super.onDestroyView();
    }

    private int minSeverity() {
        int id = severityGroup.getCheckedChipId();
        if (id == R.id.chip_graph_alerts) {
            return 1;
        }
        if (id == R.id.chip_graph_medium) {
            return 3;
        }
        if (id == R.id.chip_graph_high) {
            return 4;
        }
        return 0;
    }

    private void rebuild() {
        final NativeForensicEngine engine = viewModel.engine();
        if (engine == null || getView() == null) {
            return;
        }
        dirty = false;
        final int layout = layoutToggle.getCheckedButtonId() == R.id.btn_layout_force
                ? NativeForensicEngine.LAYOUT_FORCE_DIRECTED : NativeForensicEngine.LAYOUT_HIERARCHICAL;
        final int severity = minSeverity();
        final boolean network = networkChip.isChecked();
        final boolean dns = dnsChip.isChecked();
        final int serial = buildSerial.incrementAndGet();
        final TraceDroidApp app = TraceDroidApp.from(requireContext());
        spinner.setVisibility(View.VISIBLE);

        app.io().execute(() -> {
            GraphModel model = null;
            String error = null;
            try {
                // Geometry crosses JNI as a direct ByteBuffer and is decoded inside buildGraph().
                model = engine.buildGraph(layout, severity, network, dns, MAX_NODES, null);
            } catch (CancellationException e) {
                error = getStringSafe(R.string.msg_cancelled);
            } catch (RuntimeException e) {
                error = e.getMessage();
            }
            final GraphModel result = model;
            final String message = error;
            app.postMain(() -> {
                if (serial != buildSerial.get() || getView() == null) {
                    return;  // a newer build was requested meanwhile
                }
                spinner.setVisibility(View.GONE);
                if (result == null) {
                    summary.setText(getString(R.string.msg_failed, message));
                    return;
                }
                graphView.setModel(result);
                String text = getString(R.string.graph_summary, Formats.count(result.nodeCount),
                        Formats.count(result.edgeCount));
                if (result.truncated) {
                    text += "  ·  " + getString(R.string.graph_truncated);
                }
                if (layout == NativeForensicEngine.LAYOUT_FORCE_DIRECTED && !result.forceLayout && !result.isEmpty()) {
                    text += "  ·  " + getString(R.string.graph_force_fallback);
                }
                summary.setText(text);
            });
        });
    }

    private String getStringSafe(int res) {
        return isAdded() ? getString(res) : "";
    }
}
