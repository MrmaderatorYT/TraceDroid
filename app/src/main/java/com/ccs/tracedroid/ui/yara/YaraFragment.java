// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.yara;

import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.ui.cases.CaseViewModel;
import com.ccs.tracedroid.util.Severity;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * YARA workbench: import and compile rule files, then scan suspect binaries, memory dumps or
 * whole folders picked through the Storage Access Framework. Matches show the rule, tags,
 * metadata and a hex preview around every matched string.
 */
public final class YaraFragment extends Fragment {
    private static final String[] ANY_FILE = {"*/*"};

    private CaseViewModel caseModel;
    private YaraViewModel yaraModel;
    private final ResultAdapter adapter = new ResultAdapter();
    private ActivityResultLauncher<String[]> pickRules;
    private ActivityResultLauncher<Uri> pickRuleTree;
    private ActivityResultLauncher<String[]> pickArtifacts;
    private ActivityResultLauncher<Uri> pickArtifactTree;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        caseModel = new ViewModelProvider(requireActivity()).get(CaseViewModel.class);
        yaraModel = new ViewModelProvider(requireActivity()).get(YaraViewModel.class);
        pickRules = registerForActivityResult(new ActivityResultContracts.OpenMultipleDocuments(), uris -> {
            if (uris != null && !uris.isEmpty()) {
                caseModel.importYaraFiles(uris);
            }
        });
        pickRuleTree = registerForActivityResult(new ActivityResultContracts.OpenDocumentTree(), uri -> {
            if (uri != null) {
                caseModel.importYaraTree(uri);
            }
        });
        pickArtifacts = registerForActivityResult(new ActivityResultContracts.OpenMultipleDocuments(), uris -> {
            if (uris != null && !uris.isEmpty()) {
                yaraModel.scanDocuments(caseModel, uris);
            }
        });
        pickArtifactTree = registerForActivityResult(new ActivityResultContracts.OpenDocumentTree(), uri -> {
            if (uri != null) {
                yaraModel.scanTree(caseModel, uri);
            }
        });
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle state) {
        return inflater.inflate(R.layout.fragment_yara, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        RecyclerView list = view.findViewById(R.id.yara_results);
        list.setLayoutManager(new LinearLayoutManager(requireContext()));
        list.setAdapter(adapter);

        final TextView status = view.findViewById(R.id.yara_status);
        final TextView errorsButton = view.findViewById(R.id.btn_yara_errors);
        final View scanFiles = view.findViewById(R.id.btn_scan_files);
        final View scanFolder = view.findViewById(R.id.btn_scan_folder);
        final TextView summary = view.findViewById(R.id.yara_summary);
        final View empty = view.findViewById(R.id.yara_empty);

        view.findViewById(R.id.btn_import_yara).setOnClickListener(v -> pickRules.launch(ANY_FILE));
        view.findViewById(R.id.btn_import_yara_dir).setOnClickListener(v -> pickRuleTree.launch(null));
        view.findViewById(R.id.btn_clear_yara).setOnClickListener(v -> caseModel.clearYara());
        scanFiles.setOnClickListener(v -> pickArtifacts.launch(ANY_FILE));
        scanFolder.setOnClickListener(v -> pickArtifactTree.launch(null));
        errorsButton.setOnClickListener(v -> showCompileErrors());

        caseModel.yaraInfo().observe(getViewLifecycleOwner(), info -> {
            int rules = info.optInt("rules");
            JSONArray errors = info.optJSONArray("errors");
            int errorCount = errors == null ? 0 : errors.length();
            if (!info.optBoolean("available", true)) {
                status.setText(R.string.yara_unavailable);
            } else {
                status.setText(rules == 0 ? getString(R.string.yara_no_rules) : getString(R.string.yara_rules_loaded, rules));
            }
            errorsButton.setVisibility(errorCount > 0 ? View.VISIBLE : View.GONE);
            errorsButton.setText(getString(R.string.yara_compile_errors, errorCount));
            scanFiles.setEnabled(rules > 0);
            scanFolder.setEnabled(rules > 0);
        });
        yaraModel.results().observe(getViewLifecycleOwner(), items -> {
            adapter.submit(items);
            empty.setVisibility(items.isEmpty() ? View.VISIBLE : View.GONE);
        });
        yaraModel.summary().observe(getViewLifecycleOwner(), summary::setText);
    }

    private void showCompileErrors() {
        JSONObject info = caseModel.yaraInfo().getValue();
        JSONArray errors = info == null ? null : info.optJSONArray("errors");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; errors != null && i < errors.length(); i++) {
            sb.append(errors.optString(i)).append("\n\n");
        }
        View content = getLayoutInflater().inflate(R.layout.dialog_text, null);
        ((TextView) content.findViewById(R.id.text)).setText(sb.toString());
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.yara_errors_title)
                .setView(content)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    private static final class ResultAdapter extends RecyclerView.Adapter<ResultAdapter.Holder> {
        private List<YaraViewModel.Item> items = new ArrayList<>();

        void submit(List<YaraViewModel.Item> newItems) {
            items = newItems;
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            return new Holder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_yara_match, parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull Holder holder, int position) {
            YaraViewModel.Item item = items.get(position);
            int severity = item.kind == YaraViewModel.Item.MATCH ? 4 : item.kind == YaraViewModel.Item.ERROR ? 3 : 0;
            holder.bar.setBackgroundColor(Severity.color(holder.itemView.getContext(), severity));
            holder.rule.setText(item.title);
            holder.artifact.setText(item.artifact);
            setOrHide(holder.tags, item.tags);
            setOrHide(holder.detail, item.detail);
            setOrHide(holder.hex, item.hex);
            holder.hexScroller.setVisibility(item.hex.isEmpty() ? View.GONE : View.VISIBLE);
        }

        private static void setOrHide(TextView view, String text) {
            view.setText(text);
            view.setVisibility(text.isEmpty() ? View.GONE : View.VISIBLE);
        }

        @Override
        public int getItemCount() {
            return items.size();
        }

        static final class Holder extends RecyclerView.ViewHolder {
            final View bar;
            final TextView rule;
            final TextView artifact;
            final TextView tags;
            final TextView detail;
            final TextView hex;
            final View hexScroller;

            Holder(View view) {
                super(view);
                bar = view.findViewById(R.id.match_bar);
                rule = view.findViewById(R.id.match_rule);
                artifact = view.findViewById(R.id.match_artifact);
                tags = view.findViewById(R.id.match_tags);
                detail = view.findViewById(R.id.match_detail);
                hex = view.findViewById(R.id.match_hex);
                hexScroller = view.findViewById(R.id.match_hex_scroller);
            }
        }
    }
}
