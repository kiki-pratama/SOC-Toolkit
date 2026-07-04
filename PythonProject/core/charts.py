import altair as alt
import pandas as pd
import streamlit as st


CATEGORY_ORDER = [
    "Malicious",
    "Suspicious",
    "Clean",
    "Invalid",
    "Error",
]

CATEGORY_COLORS = {
    "Malicious": "#ef4444",
    "Suspicious": "#facc15",
    "Clean": "#22c55e",
    "Invalid": "#9ca3af",
    "Error": "#6b7280",
}


def render_risk_distribution_chart(df: pd.DataFrame) -> None:
    st.caption("Risk Distribution")

    category_counts = (
        df["Category"]
        .fillna("Unknown")
        .value_counts()
        .reindex(CATEGORY_ORDER, fill_value=0)
        .reset_index()
    )

    category_counts.columns = ["Category", "Count"]
    category_counts = category_counts[category_counts["Count"] > 0]

    if category_counts.empty:
        st.info("Tidak ada risk data.")
        return

    chart = (
        alt.Chart(category_counts)
        .mark_bar(
            cornerRadiusTopLeft=6,
            cornerRadiusTopRight=6,
        )
        .encode(
            x=alt.X(
                "Category:N",
                sort=CATEGORY_ORDER,
                title=None,
                axis=alt.Axis(
                    labelAngle=0,
                    labelColor="#d1d5db",
                    titleColor="#d1d5db",
                ),
            ),
            y=alt.Y(
                "Count:Q",
                title="Count",
                axis=alt.Axis(
                    labelColor="#d1d5db",
                    titleColor="#d1d5db",
                    gridColor="#374151",
                ),
            ),
            color=alt.Color(
                "Category:N",
                scale=alt.Scale(
                    domain=list(CATEGORY_COLORS.keys()),
                    range=list(CATEGORY_COLORS.values()),
                ),
                legend=None,
            ),
            tooltip=[
                alt.Tooltip("Category:N", title="Category"),
                alt.Tooltip("Count:Q", title="Count"),
            ],
        )
        .properties(
            height=340,
            background="transparent",
        )
        .configure_view(
            strokeWidth=0,
        )
        .configure_axis(
            domainColor="#4b5563",
            tickColor="#4b5563",
            labelFontSize=12,
            titleFontSize=12,
        )
    )

    st.altair_chart(chart, use_container_width=True, theme=None)


def render_country_origin_chart(df: pd.DataFrame) -> None:
    st.caption("Country Origin")

    country_counts = (
        df["Country"]
        .fillna("-")
        .astype(str)
        .str.strip()
    )

    country_counts = (
        country_counts[~country_counts.isin(["-", "", "None", "nan"])]
        .value_counts()
        .head(10)
        .reset_index()
    )

    country_counts.columns = ["Country", "Count"]

    if country_counts.empty:
        st.info("Tidak ada country data.")
        return

    chart = (
        alt.Chart(country_counts)
        .mark_bar(
            cornerRadiusTopRight=6,
            cornerRadiusBottomRight=6,
        )
        .encode(
            y=alt.Y(
                "Country:N",
                sort="-x",
                title=None,
                axis=alt.Axis(
                    labelColor="#d1d5db",
                    titleColor="#d1d5db",
                ),
            ),
            x=alt.X(
                "Count:Q",
                title="Count",
                axis=alt.Axis(
                    labelColor="#d1d5db",
                    titleColor="#d1d5db",
                    gridColor="#374151",
                ),
            ),
            color=alt.Color(
                "Count:Q",
                scale=alt.Scale(
                    range=[
                        "#38bdf8",
                        "#2563eb",
                    ],
                ),
                legend=None,
            ),
            tooltip=[
                alt.Tooltip("Country:N", title="Country"),
                alt.Tooltip("Count:Q", title="Count"),
            ],
        )
        .properties(
            height=340,
            background="transparent",
        )
        .configure_view(
            strokeWidth=0,
        )
        .configure_axis(
            domainColor="#4b5563",
            tickColor="#4b5563",
            labelFontSize=12,
            titleFontSize=12,
        )
    )

    st.altair_chart(chart, use_container_width=True, theme=None)


def render_top_isp_chart(df: pd.DataFrame) -> None:
    st.caption("Top ISP / Provider")

    isp_counts = (
        df["ISP"]
        .fillna("-")
        .astype(str)
        .str.strip()
    )

    isp_counts = (
        isp_counts[~isp_counts.isin(["-", "", "None", "nan"])]
        .value_counts()
        .head(10)
        .reset_index()
    )

    isp_counts.columns = ["ISP", "Count"]

    if isp_counts.empty:
        st.info("Tidak ada ISP data.")
        return

    chart = (
        alt.Chart(isp_counts)
        .mark_bar(
            cornerRadiusTopRight=6,
            cornerRadiusBottomRight=6,
        )
        .encode(
            y=alt.Y(
                "ISP:N",
                sort="-x",
                title=None,
                axis=alt.Axis(
                    labelColor="#d1d5db",
                    titleColor="#d1d5db",
                    labelLimit=360,
                ),
            ),
            x=alt.X(
                "Count:Q",
                title="Count",
                axis=alt.Axis(
                    labelColor="#d1d5db",
                    titleColor="#d1d5db",
                    gridColor="#374151",
                ),
            ),
            color=alt.Color(
                "Count:Q",
                scale=alt.Scale(
                    range=[
                        "#818cf8",
                        "#4f46e5",
                    ],
                ),
                legend=None,
            ),
            tooltip=[
                alt.Tooltip("ISP:N", title="ISP"),
                alt.Tooltip("Count:Q", title="Count"),
            ],
        )
        .properties(
            height=380,
            background="transparent",
        )
        .configure_view(
            strokeWidth=0,
        )
        .configure_axis(
            domainColor="#4b5563",
            tickColor="#4b5563",
            labelFontSize=11,
            titleFontSize=12,
        )
    )

    st.altair_chart(chart, use_container_width=True, theme=None)
