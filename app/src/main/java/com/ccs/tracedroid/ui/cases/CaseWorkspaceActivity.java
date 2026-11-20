// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.cases;

import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.data.ForensicCase;
import com.ccs.tracedroid.ui.graph.GraphFragment;
import com.ccs.tracedroid.ui.timeline.TimelineFragment;
import com.ccs.tracedroid.ui.yara.YaraFragment;
import com.ccs.tracedroid.util.Ui;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.google.android.material.snackbar.Snackbar;

/**
 * Workspace of one open case: hosts the overview, timeline, graph and YARA screens and shows
 * the shared progress of native background work.
 */
public final class CaseWorkspaceActivity extends AppCompatActivity {
    public static final String EXTRA_CASE_ID = "case_id";
    private static final String TAG_PREFIX = "tab_";

    private CaseViewModel viewModel;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_workspace);
        Ui.applySystemBarInsets(findViewById(R.id.root));

        viewModel = new ViewModelProvider(this).get(CaseViewModel.class);
        if (!viewModel.open(getIntent().getStringExtra(EXTRA_CASE_ID))) {
            finish();
            return;
        }
        ForensicCase c = viewModel.forensicCase();

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setTitle(c == null ? getString(R.string.app_name) : c.name);
        toolbar.setNavigationOnClickListener(v -> finish());

        LinearProgressIndicator bar = findViewById(R.id.progress);
        TextView status = findViewById(R.id.status);
        View statusRow = findViewById(R.id.status_row);
        findViewById(R.id.cancel).setOnClickListener(v -> viewModel.cancelCurrent());
        viewModel.progress().observe(this, p -> {
            statusRow.setVisibility(p.busy ? View.VISIBLE : View.GONE);
            status.setText(p.percent >= 0 ? getString(R.string.status_percent, p.label, p.percent) : p.label);
            if (p.percent >= 0) {
                // Switching a visible indicator between modes requires hiding it first.
                if (bar.isIndeterminate()) {
                    bar.setVisibility(View.INVISIBLE);
                    bar.setIndeterminate(false);
                    bar.setVisibility(View.VISIBLE);
                }
                bar.setProgressCompat(p.percent, true);
            } else if (!bar.isIndeterminate()) {
                bar.setVisibility(View.INVISIBLE);
                bar.setIndeterminate(true);
                bar.setVisibility(View.VISIBLE);
            }
        });
        viewModel.message().observe(this, text -> {
            if (text != null) {
                Snackbar.make(findViewById(R.id.fragment_container), text, Snackbar.LENGTH_LONG)
                        .setAnchorView(R.id.bottom_nav).show();
                viewModel.consumeMessage();
            }
        });

        BottomNavigationView nav = findViewById(R.id.bottom_nav);
        nav.setOnItemSelectedListener(item -> {
            show(item.getItemId());
            return true;
        });
        if (savedInstanceState == null) {
            show(R.id.nav_overview);
        }
    }

    /** Switches tabs with show/hide so each screen keeps its scroll position, filters and viewport. */
    private void show(int itemId) {
        String tag = TAG_PREFIX + itemId;
        androidx.fragment.app.FragmentManager fm = getSupportFragmentManager();
        androidx.fragment.app.FragmentTransaction tx = fm.beginTransaction().setReorderingAllowed(true);
        for (Fragment f : fm.getFragments()) {
            if (f.getTag() != null && f.getTag().startsWith(TAG_PREFIX)) {
                tx.hide(f);
            }
        }
        Fragment target = fm.findFragmentByTag(tag);
        if (target == null) {
            tx.add(R.id.fragment_container, create(itemId), tag);
        } else {
            tx.show(target);
        }
        tx.commit();
    }

    private static Fragment create(int itemId) {
        if (itemId == R.id.nav_timeline) {
            return new TimelineFragment();
        }
        if (itemId == R.id.nav_graph) {
            return new GraphFragment();
        }
        if (itemId == R.id.nav_yara) {
            return new YaraFragment();
        }
        return new OverviewFragment();
    }

    /** Lets other screens jump to a tab (e.g. overview "open timeline filtered by alerts"). */
    public void selectTab(int itemId) {
        BottomNavigationView nav = findViewById(R.id.bottom_nav);
        nav.setSelectedItemId(itemId);
    }
}
