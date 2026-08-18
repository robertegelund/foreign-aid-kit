import { loadAllAidData } from "./oecd-api.js";

let chart = null;

// Creates the time-series chart on first call, and swaps its data in place
// on later calls (used when switching between the Africa-wide view and a
// selected country's own history).
export const showAidTimeSeries = (series, seriesName) => {
    const years = series.map(point => point.name);
    const maxValue = Math.max(...series.map(point => point.y));
    const yAxisMax = Math.ceil(maxValue * 1.1 / 100) * 100;

    if (chart) {
        chart.xAxis[0].setCategories(years);
        chart.yAxis[0].update({ max: yAxisMax });
        chart.series[0].update({ name: seriesName, data: series });
        return;
    }

    chart = new Highcharts.Chart({
        chart: {
            renderTo: "aid-graph-timeseries",
            type: "line",
            backgroundColor: "transparent",
        },
        title: false,
        series: [
            {
                name: seriesName,
                data: series,
                color: "gold"
            }
        ],
        xAxis: {
            categories: years,
            labels: {
                style: {
                    color: "white"
                }
            }
        },
        yAxis: {
            min: 0,
            max: yAxisMax,
            title: "",
            labels: {
                style: {
                    color: "white"
                }
            }
        },
        legend: {
            enabled: false
        }
    });
};

const initAidTimeSeries = async () => {
    try {
        const allAidData = await loadAllAidData();
        showAidTimeSeries(allAidData["F"], "Aid from Norway to Africa (million USD)");
    } catch (error) {
        console.error("Failed to load aid time series from the OECD API:", error);
    }
};

initAidTimeSeries();
