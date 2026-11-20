// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.timeline;

import android.graphics.Typeface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.graphics.ColorUtils;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.ViewModelProvider;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.TraceDroidApp;
import com.ccs.tracedroid.jni.NativeForensicEngine;
import com.ccs.tracedroid.ui.cases.CaseViewModel;
import com.ccs.tracedroid.util.Severity;
import com.ccs.tracedroid.util.Ui;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Bottom sheet with every field of one event, the Sigma alerts that fired on it and its raw XML. */
public final class EventDetailSheet extends BottomSheetDialogFragment {
    private static final String ARG_INDEX = "event_index";

    public static void show(FragmentManager fm, int eventIndex) {
        EventDetailSheet sheet = new EventDetailSheet();
        Bundle args = new Bundle();
        args.putInt(ARG_INDEX, eventIndex);
        sheet.setArguments(args);
        sheet.show(fm, "event_detail");
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle state) {
        return inflater.inflate(R.layout.sheet_detail, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        final LinearLayout content = view.findViewById(R.id.content);
        final CaseViewModel viewModel = new ViewModelProvider(requireActivity()).get(CaseViewModel.class);
        final NativeForensicEngine engine = viewModel.engine();
        final int index = requireArguments().getInt(ARG_INDEX);
        if (engine == null) {
            dismissAllowingStateLoss();
            return;
        }
        final TraceDroidApp app = TraceDroidApp.from(requireContext());
        app.io().execute(() -> {
            JSONObject detail = null;
            String error = null;
            try {
                detail = new JSONObject(engine.eventDetail(index));
            } catch (JSONException | RuntimeException e) {
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

    private void bind(LinearLayout content, JSONObject event) {
        int severity = event.optInt("severity");
        Ui.addText(content, getString(R.string.event_heading, event.optInt("eventId"), event.optString("title")), 18, true);
        Ui.addText(content, event.optString("time") + " UTC  ·  " + event.optString("computer"), 13, false)
                .setAlpha(0.8f);

        JSONArray alerts = event.optJSONArray("alerts");
        if (alerts != null && alerts.length() > 0) {
            Ui.addHeading(content, getString(R.string.sigma_alerts));
            for (int i = 0; i < alerts.length(); i++) {
                JSONObject alert = alerts.optJSONObject(i);
                if (alert != null) {
                    addAlert(content, alert);
                }
            }
        }

        // Fields that satisfied a rule are tinted with the event's severity colour.
        int highlight = ColorUtils.setAlphaComponent(Severity.color(requireContext(), Math.max(severity, 1)), 0x40);
        Ui.addHeading(content, getString(R.string.event_fields));
        Ui.addField(content, "Channel", event.optString("channel"), event.optBoolean("channelHit") ? highlight : 0);
        Ui.addField(content, "Provider", event.optString("provider"), 0);
        Ui.addField(content, "EventID", String.valueOf(event.optInt("eventId")), event.optBoolean("eventIdHit") ? highlight : 0);
        Ui.addField(content, "EventRecordID", String.valueOf(event.optLong("recordId")), 0);
        JSONArray fields = event.optJSONArray("fields");
        for (int i = 0; fields != null && i < fields.length(); i++) {
            JSONObject field = fields.optJSONObject(i);
            if (field != null) {
                Ui.addField(content, field.optString("k"), field.optString("v"), field.optBoolean("hit") ? highlight : 0);
            }
        }
        Ui.addField(content, getString(R.string.evidence_file), event.optString("source"), 0);

        String xml = event.optString("xml");
        if (!xml.isEmpty()) {
            Ui.addHeading(content, getString(R.string.raw_xml));
            TextView text = new TextView(requireContext());
            text.setText(xml);
            text.setTextSize(11);
            text.setTypeface(Typeface.MONOSPACE);
            text.setTextIsSelectable(true);
            HorizontalScrollView scroller = new HorizontalScrollView(requireContext());
            scroller.addView(text);
            content.addView(scroller);
        }
    }

    public static void addAlert(LinearLayout content, JSONObject alert) {
        View card = LayoutInflater.from(content.getContext()).inflate(R.layout.item_rule_hit, content, false);
        int level = alert.optInt("level");
        card.findViewById(R.id.rule_badge).setBackgroundColor(Severity.color(content.getContext(), level));
        ((TextView) card.findViewById(R.id.rule_title)).setText(alert.optString("title"));
        StringBuilder meta = new StringBuilder(Severity.name(content.getContext(), level));
        JSONArray matched = alert.optJSONArray("fields");
        if (matched != null && matched.length() > 0) {
            meta.append("  ·  ");
            for (int i = 0; i < matched.length(); i++) {
                meta.append(i == 0 ? "" : ", ").append(matched.optString(i));
            }
        }
        JSONArray tags = alert.optJSONArray("tags");
        if (tags != null && tags.length() > 0) {
            meta.append('\n');
            for (int i = 0; i < tags.length(); i++) {
                meta.append(i == 0 ? "" : "  ").append(tags.optString(i));
            }
        }
        String time = alert.optString("time");
        if (!time.isEmpty()) {
            meta.append('\n').append(time).append(" UTC  ·  EID ").append(alert.optInt("eventId"));
        }
        ((TextView) card.findViewById(R.id.rule_meta)).setText(meta);
        content.addView(card);
    }
}
