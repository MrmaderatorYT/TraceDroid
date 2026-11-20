// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.cases;

import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.data.ForensicCase;
import com.ccs.tracedroid.util.Formats;
import com.ccs.tracedroid.util.Severity;
import com.ccs.tracedroid.util.Ui;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/** Case workspace home: evidence import, index statistics and the Sigma alert summary. */
public final class OverviewFragment extends Fragment {
    private static final String[] ANY_FILE = {"*/*"};

    private CaseViewModel viewModel;
    private ActivityResultLauncher<String[]> pickEvtx;
    private ActivityResultLauncher<String[]> pickSigmaFiles;
    private ActivityResultLauncher<Uri> pickSigmaTree;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        viewModel = new ViewModelProvider(requireActivity()).get(CaseViewModel.class);
        // The Storage Access Framework grants per-document access; no storage permission is needed.
        pickEvtx = registerForActivityResult(new ActivityResultContracts.OpenMultipleDocuments(),
                uris -> nonEmpty(uris, viewModel::importEvtx));
        pickSigmaFiles = registerForActivityResult(new ActivityResultContracts.OpenMultipleDocuments(),
                uris -> nonEmpty(uris, viewModel::importSigmaFiles));
        pickSigmaTree = registerForActivityResult(new ActivityResultContracts.OpenDocumentTree(), uri -> {
            if (uri != null) {
                viewModel.importSigmaTree(uri);
            }
        });
    }

    private interface UriSink {
        void accept(List<Uri> uris);
    }

    private static void nonEmpty(List<Uri> uris, UriSink sink) {
        if (uris != null && !uris.isEmpty()) {
            sink.accept(uris);
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle state) {
        return inflater.inflate(R.layout.fragment_overview, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        ForensicCase c = viewModel.forensicCase();
        if (c != null) {
            String examiner = c.examiner.isEmpty() ? getString(R.string.examiner_unknown) : c.examiner;
            ((TextView) view.findViewById(R.id.case_info)).setText(
                    getString(R.string.case_info, examiner, Formats.utcMinutes(c.createdAtMs)));
            TextView notes = view.findViewById(R.id.case_notes);
            notes.setText(c.notes);
            notes.setVisibility(c.notes.isEmpty() ? View.GONE : View.VISIBLE);
        }

        view.findViewById(R.id.btn_import_evtx).setOnClickListener(v -> pickEvtx.launch(ANY_FILE));
        view.findViewById(R.id.btn_import_sigma).setOnClickListener(v -> pickSigmaFiles.launch(ANY_FILE));
        view.findViewById(R.id.btn_import_sigma_dir).setOnClickListener(v -> pickSigmaTree.launch(null));
        view.findViewById(R.id.btn_rescan).setOnClickListener(v -> viewModel.rescanSigma());
        view.findViewById(R.id.btn_clear_sigma).setOnClickListener(v -> viewModel.clearSigma());
        view.findViewById(R.id.btn_rebuild).setOnClickListener(v -> viewModel.rebuildIndex());
        view.findViewById(R.id.btn_custody).setOnClickListener(v -> showCustodyLog());
        view.findViewById(R.id.btn_skipped).setOnClickListener(v -> showSkippedRules());

        viewModel.stats().observe(getViewLifecycleOwner(), stats -> bindStats(view, stats));
        viewModel.sigmaSummary().observe(getViewLifecycleOwner(), summary -> bindSigma(view, summary));
    }

    private void bindStats(View view, JSONObject stats) {
        long events = stats.optLong("events");
        ((TextView) view.findViewById(R.id.stat_events)).setText(Formats.count(events));
        ((TextView) view.findViewById(R.id.stat_sysmon)).setText(Formats.count(stats.optLong("sysmonEvents")));
        ((TextView) view.findViewById(R.id.stat_processes)).setText(Formats.count(stats.optLong("processCreates")));
        ((TextView) view.findViewById(R.id.stat_index)).setText(Formats.bytes(stats.optLong("indexBytes")));
        TextView range = view.findViewById(R.id.stat_range);
        range.setText(events == 0 ? getString(R.string.no_events)
                : getString(R.string.time_range, stats.optString("firstTime"), stats.optString("lastTime")));
        JSONArray sources = stats.optJSONArray("sources");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; sources != null && i < sources.length(); i++) {
            sb.append(i == 0 ? "" : "\n").append("• ").append(sources.optString(i));
        }
        ((TextView) view.findViewById(R.id.stat_sources)).setText(
                sb.length() == 0 ? getString(R.string.no_evidence) : sb.toString());
    }

    private void bindSigma(View view, JSONObject summary) {
        long rules = summary.optLong("rules");
        long skipped = summary.optLong("skipped");
        ((TextView) view.findViewById(R.id.sigma_status)).setText(getString(R.string.sigma_status,
                Formats.count(rules), Formats.count(summary.optLong("hits")),
                Formats.count(summary.optLong("alertEvents"))));
        TextView skippedButton = view.findViewById(R.id.btn_skipped);
        skippedButton.setVisibility(skipped > 0 ? View.VISIBLE : View.GONE);
        skippedButton.setText(getString(R.string.skipped_rules, skipped));

        LinearLayout list = view.findViewById(R.id.rule_hits);
        list.removeAllViews();
        JSONArray hits = summary.optJSONArray("ruleHits");
        int shown = hits == null ? 0 : Math.min(hits.length(), 60);
        for (int i = 0; i < shown; i++) {
            JSONObject hit = hits.optJSONObject(i);
            if (hit == null) {
                continue;
            }
            View row = getLayoutInflater().inflate(R.layout.item_rule_hit, list, false);
            int level = hit.optInt("level");
            row.findViewById(R.id.rule_badge).setBackgroundColor(Severity.color(requireContext(), level));
            ((TextView) row.findViewById(R.id.rule_title)).setText(hit.optString("title"));
            ((TextView) row.findViewById(R.id.rule_meta)).setText(getString(R.string.rule_meta,
                    Severity.name(requireContext(), level), Formats.count(hit.optLong("count"))));
            final String description = hit.optString("description");
            final String title = hit.optString("title");
            row.setOnClickListener(v -> new MaterialAlertDialogBuilder(requireContext())
                    .setTitle(title)
                    .setMessage(description.isEmpty() ? hit.optString("id") : description + "\n\n" + hit.optString("id"))
                    .setPositiveButton(android.R.string.ok, null)
                    .show());
            list.addView(row);
        }
        if (shown == 0) {
            TextView empty = Ui.addText(list, getString(rules == 0 ? R.string.no_rules : R.string.no_alerts), 14, false);
            empty.setAlpha(0.7f);
        }
    }

    private void showCustodyLog() {
        ForensicCase c = viewModel.forensicCase();
        if (c == null) {
            return;
        }
        String log = viewModel.repository().custodyLog(c);
        showMonospaceDialog(getString(R.string.custody_log), log.isEmpty() ? getString(R.string.no_evidence) : log);
    }

    private void showSkippedRules() {
        JSONObject summary = viewModel.sigmaSummary().getValue();
        JSONArray diagnostics = summary == null ? null : summary.optJSONArray("diagnostics");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; diagnostics != null && i < diagnostics.length(); i++) {
            JSONObject d = diagnostics.optJSONObject(i);
            if (d == null) {
                continue;
            }
            String title = d.optString("title");
            sb.append(title.isEmpty() ? d.optString("file") : title).append("\n    ")
                    .append(d.optString("message")).append("\n\n");
        }
        showMonospaceDialog(getString(R.string.skipped_title), sb.toString());
    }

    private void showMonospaceDialog(String title, String body) {
        View content = getLayoutInflater().inflate(R.layout.dialog_text, null);
        ((TextView) content.findViewById(R.id.text)).setText(body);
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle(title)
                .setView(content)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }
}
