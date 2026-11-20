// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.graph;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.ViewModelProvider;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.TraceDroidApp;
import com.ccs.tracedroid.jni.NativeForensicEngine;
import com.ccs.tracedroid.model.GraphModel;
import com.ccs.tracedroid.ui.cases.CaseViewModel;
import com.ccs.tracedroid.ui.timeline.EventDetailSheet;
import com.ccs.tracedroid.util.Severity;
import com.ccs.tracedroid.util.Ui;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.button.MaterialButton;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Bottom-sheet inspector for a graph node: full command line, hashes, parent chain and the
 * Sigma alerts attributed to the process (or the connection / DNS details for activity nodes).
 */
public final class NodeInspectorSheet extends BottomSheetDialogFragment {
    private static final String ARG_NODE = "node";

    public static void show(FragmentManager fm, int node) {
        NodeInspectorSheet sheet = new NodeInspectorSheet();
        Bundle args = new Bundle();
        args.putInt(ARG_NODE, node);
        sheet.setArguments(args);
        sheet.show(fm, "node_inspector");
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle state) {
        return inflater.inflate(R.layout.sheet_detail, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        final LinearLayout content = view.findViewById(R.id.content);
        final NativeForensicEngine engine = new ViewModelProvider(requireActivity()).get(CaseViewModel.class).engine();
        final int node = requireArguments().getInt(ARG_NODE);
        if (engine == null) {
            dismissAllowingStateLoss();
            return;
        }
        final TraceDroidApp app = TraceDroidApp.from(requireContext());
        app.io().execute(() -> {
            JSONObject detail = null;
            String error = null;
            try {
                detail = new JSONObject(engine.graphNodeDetail(node));
            } catch (JSONException | RuntimeException e) {
                // The graph may have been rebuilt since the tap; the index is then stale.
                error = e.getMessage();
            }
            final JSONObject result = detail;
            final String message = error;
            app.postMain(() -> {
                if (getView() == null) {
                    return;
                }
                if (result == null) {
                    Ui.addText(content, getString(R.string.msg_failed, message), 14, false);
                } else {
                    bind(content, result);
                }
            });
        });
    }

    private void bind(LinearLayout content, JSONObject node) {
        int type = node.optInt("type");
        int severity = node.optInt("severity");
        Ui.addText(content, node.optString("label"), 18, true);
        String kind = getString(type == GraphModel.TYPE_PROCESS ? R.string.node_process
                : type == GraphModel.TYPE_NETWORK ? R.string.node_network : R.string.node_dns);
        StringBuilder sub = new StringBuilder(kind);
        if (severity > 0) {
            sub.append("  ·  ").append(Severity.name(requireContext(), severity));
        }
        if (node.optBoolean("synthetic")) {
            sub.append("  ·  ").append(getString(R.string.node_synthetic));
        }
        Ui.addText(content, sub, 13, false).setAlpha(0.8f);

        Ui.addHeading(content, getString(R.string.node_details));
        if (type == GraphModel.TYPE_PROCESS) {
            Ui.addField(content, "CommandLine", node.optString("commandLine"), 0);
            Ui.addField(content, "Image", node.optString("image"), 0);
            Ui.addField(content, "ProcessId", node.optInt("pid") == 0 ? "" : String.valueOf(node.optInt("pid")), 0);
            Ui.addField(content, "User", node.optString("user"), 0);
            Ui.addField(content, "SHA256", node.optString("sha256"), 0);
            Ui.addField(content, "Hashes", node.optString("hashes"), 0);
            Ui.addField(content, "ProcessGuid", node.optString("guid"), 0);
            Ui.addField(content, "ParentCommandLine", node.optString("parentCommandLine"), 0);
            Ui.addField(content, getString(R.string.node_started), node.optString("time"), 0);
            Ui.addField(content, getString(R.string.node_ended), node.optString("endTime"), 0);
            Ui.addField(content, getString(R.string.node_activity), getString(R.string.node_activity_value,
                    node.optInt("childProcesses"), node.optInt("connections"), node.optInt("dnsQueries")), 0);
        } else if (type == GraphModel.TYPE_NETWORK) {
            Ui.addField(content, "Destination", node.optString("destinationIp") + ":" + node.optString("destinationPort"), 0);
            Ui.addField(content, "DestinationHostname", node.optString("destinationHostname"), 0);
            Ui.addField(content, "Protocol", node.optString("protocol"), 0);
            Ui.addField(content, "Source", node.optString("sourceIp") + ":" + node.optString("sourcePort"), 0);
            Ui.addField(content, "Image", node.optString("image"), 0);
            Ui.addField(content, getString(R.string.node_first_seen), node.optString("time"), 0);
            Ui.addField(content, getString(R.string.node_count), String.valueOf(node.optInt("count")), 0);
        } else {
            Ui.addField(content, "QueryName", node.optString("queryName"), 0);
            Ui.addField(content, "QueryResults", node.optString("queryResults"), 0);
            Ui.addField(content, "Image", node.optString("image"), 0);
            Ui.addField(content, getString(R.string.node_first_seen), node.optString("time"), 0);
            Ui.addField(content, getString(R.string.node_count), String.valueOf(node.optInt("count")), 0);
        }
        Ui.addField(content, "Computer", node.optString("computer"), 0);

        JSONArray chain = node.optJSONArray("parentChain");
        if (chain != null && chain.length() > 0) {
            Ui.addHeading(content, getString(R.string.node_parent_chain));
            StringBuilder indent = new StringBuilder();
            // Stored nearest-parent first; display from the root down to this node.
            for (int i = chain.length() - 1; i >= 0; i--) {
                JSONObject parent = chain.optJSONObject(i);
                if (parent == null) {
                    continue;
                }
                String image = parent.optString("image");
                Ui.addField(content, indent + "└ " + parent.optString("label"), image.isEmpty() ? " " : image, 0);
                indent.append("  ");
            }
        }

        JSONArray alerts = node.optJSONArray("alerts");
        Ui.addHeading(content, getString(R.string.sigma_alerts));
        if (alerts == null || alerts.length() == 0) {
            Ui.addText(content, getString(R.string.no_alerts_node), 14, false).setAlpha(0.7f);
        } else {
            for (int i = 0; i < alerts.length(); i++) {
                JSONObject alert = alerts.optJSONObject(i);
                if (alert != null) {
                    EventDetailSheet.addAlert(content, alert);
                }
            }
        }

        final int eventIndex = node.optInt("eventIndex", -1);
        if (eventIndex >= 0) {
            MaterialButton open = new MaterialButton(requireContext(), null,
                    com.google.android.material.R.attr.materialButtonOutlinedStyle);
            open.setText(R.string.open_event);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.topMargin = Ui.dp(requireContext(), 16);
            open.setOnClickListener(v -> EventDetailSheet.show(getParentFragmentManager(), eventIndex));
            content.addView(open, lp);
        }
    }
}
