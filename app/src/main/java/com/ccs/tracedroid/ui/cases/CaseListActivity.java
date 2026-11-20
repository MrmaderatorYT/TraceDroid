// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.cases;

import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.TraceDroidApp;
import com.ccs.tracedroid.data.CaseRepository;
import com.ccs.tracedroid.data.ForensicCase;
import com.ccs.tracedroid.util.Formats;
import com.ccs.tracedroid.util.Ui;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** Launcher screen: the list of forensic cases stored on this device. */
public final class CaseListActivity extends AppCompatActivity {
    private CaseRepository repository;
    private final CaseAdapter adapter = new CaseAdapter();
    private View emptyView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_case_list);
        Ui.applySystemBarInsets(findViewById(R.id.root));
        repository = new CaseRepository(this);

        RecyclerView list = findViewById(R.id.case_list);
        list.setLayoutManager(new LinearLayoutManager(this));
        list.setAdapter(adapter);
        emptyView = findViewById(R.id.empty);
        findViewById(R.id.fab_new_case).setOnClickListener(v -> showCreateDialog());
    }

    @Override
    protected void onResume() {
        super.onResume();
        reload();
    }

    private void reload() {
        TraceDroidApp app = TraceDroidApp.from(this);
        app.io().execute(() -> {
            List<ForensicCase> cases = repository.list();
            List<String> details = new ArrayList<>(cases.size());
            for (ForensicCase c : cases) {
                details.add(getString(R.string.case_evidence_counts,
                        repository.files(c, CaseRepository.KIND_EVTX).size(),
                        repository.files(c, CaseRepository.KIND_SIGMA).size(),
                        repository.files(c, CaseRepository.KIND_YARA).size()));
            }
            app.postMain(() -> {
                adapter.submit(cases, details);
                emptyView.setVisibility(cases.isEmpty() ? View.VISIBLE : View.GONE);
            });
        });
    }

    private void showCreateDialog() {
        View form = LayoutInflater.from(this).inflate(R.layout.dialog_new_case, null);
        TextInputEditText name = form.findViewById(R.id.input_name);
        TextInputEditText examiner = form.findViewById(R.id.input_examiner);
        TextInputEditText notes = form.findViewById(R.id.input_notes);
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.new_case)
                .setView(form)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.create, (dialog, which) -> {
                    String caseName = text(name);
                    if (TextUtils.isEmpty(caseName)) {
                        caseName = getString(R.string.case_default_name, Formats.utcMinutes(System.currentTimeMillis()));
                    }
                    try {
                        open(repository.create(caseName, text(examiner), text(notes)));
                    } catch (IOException e) {
                        Snackbar.make(findViewById(R.id.root), getString(R.string.msg_failed, e.getMessage()),
                                Snackbar.LENGTH_LONG).show();
                    }
                })
                .show();
    }

    private static String text(TextInputEditText input) {
        return input.getText() == null ? "" : input.getText().toString().trim();
    }

    private void open(ForensicCase c) {
        startActivity(new Intent(this, CaseWorkspaceActivity.class).putExtra(CaseWorkspaceActivity.EXTRA_CASE_ID, c.id));
    }

    private void confirmDelete(ForensicCase c) {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.delete_case)
                .setMessage(getString(R.string.delete_case_message, c.name))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.delete, (dialog, which) ->
                        TraceDroidApp.from(this).io().execute(() -> {
                            repository.delete(c);
                            reload();
                        }))
                .show();
    }

    private final class CaseAdapter extends RecyclerView.Adapter<CaseAdapter.Holder> {
        private List<ForensicCase> cases = new ArrayList<>();
        private List<String> details = new ArrayList<>();

        void submit(List<ForensicCase> newCases, List<String> newDetails) {
            cases = newCases;
            details = newDetails;
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            return new Holder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_case, parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull Holder holder, int position) {
            ForensicCase c = cases.get(position);
            holder.name.setText(c.name);
            String who = c.examiner.isEmpty() ? "" : c.examiner + "  ·  ";
            holder.meta.setText(getString(R.string.case_meta, who, Formats.utcMinutes(c.createdAtMs)));
            holder.evidence.setText(details.get(position));
            holder.itemView.setOnClickListener(v -> open(c));
            holder.itemView.setOnLongClickListener(v -> {
                confirmDelete(c);
                return true;
            });
        }

        @Override
        public int getItemCount() {
            return cases.size();
        }

        final class Holder extends RecyclerView.ViewHolder {
            final TextView name;
            final TextView meta;
            final TextView evidence;

            Holder(View view) {
                super(view);
                name = view.findViewById(R.id.case_name);
                meta = view.findViewById(R.id.case_meta);
                evidence = view.findViewById(R.id.case_evidence);
            }
        }
    }
}
