// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.util;

import android.content.Context;
import android.graphics.Typeface;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.ColorInt;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.android.material.color.MaterialColors;

/** Small view helpers shared by the screens and bottom sheets. */
public final class Ui {
    private Ui() {
    }

    /** Pads {@code root} by the system bars and the IME so content is never drawn underneath them. */
    public static void applySystemBarInsets(View root) {
        ViewCompat.setOnApplyWindowInsetsListener(root, (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                    | WindowInsetsCompat.Type.displayCutout() | WindowInsetsCompat.Type.ime());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return WindowInsetsCompat.CONSUMED;
        });
    }

    public static int dp(Context context, float dp) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, dp,
                context.getResources().getDisplayMetrics()));
    }

    @ColorInt
    public static int themeColor(View view, int attr) {
        return MaterialColors.getColor(view, attr);
    }

    /** Section heading inside a detail sheet. */
    public static TextView addHeading(LinearLayout parent, CharSequence text) {
        TextView view = new TextView(parent.getContext());
        view.setText(text);
        view.setTextSize(13);
        view.setAllCaps(true);
        view.setLetterSpacing(0.08f);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        view.setTextColor(themeColor(parent, com.google.android.material.R.attr.colorPrimary));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(parent.getContext(), 18);
        lp.bottomMargin = dp(parent.getContext(), 6);
        parent.addView(view, lp);
        return view;
    }

    /** Label + selectable monospace value row; rows with an empty value are skipped. */
    public static void addField(LinearLayout parent, CharSequence key, CharSequence value, @ColorInt int highlight) {
        if (TextUtils.isEmpty(value)) {
            return;
        }
        Context context = parent.getContext();
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(context, 6);
        row.setPadding(pad, pad / 2, pad, pad / 2);
        if (highlight != 0) {
            row.setBackgroundColor(highlight);
        }

        TextView label = new TextView(context);
        label.setText(key);
        label.setTextSize(11);
        label.setTextColor(themeColor(parent, com.google.android.material.R.attr.colorOnSurfaceVariant));
        row.addView(label);

        TextView text = new TextView(context);
        text.setText(value);
        text.setTextSize(13);
        text.setTypeface(Typeface.MONOSPACE);
        text.setTextIsSelectable(true);
        text.setTextColor(themeColor(parent, com.google.android.material.R.attr.colorOnSurface));
        row.addView(text);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(context, 2);
        parent.addView(row, lp);
    }

    /** Plain paragraph text. */
    public static TextView addText(LinearLayout parent, CharSequence value, float sizeSp, boolean bold) {
        TextView text = new TextView(parent.getContext());
        text.setText(value);
        text.setTextSize(sizeSp);
        if (bold) {
            text.setTypeface(Typeface.DEFAULT_BOLD);
        }
        text.setTextColor(themeColor(parent, com.google.android.material.R.attr.colorOnSurface));
        parent.addView(text, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        return text;
    }
}
