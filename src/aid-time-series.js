import { fetchAidTimeSeries } from "./oecd-api.js";

const showAidTimeSeries = async () => {
    let aidAndYear;
    try {
        aidAndYear = await fetchAidTimeSeries();
    } catch (error) {
        console.error("Failed to load aid time series from the OECD API:", error);
        return;
    }

    const years = aidAndYear.map(aidYear => aidYear.name);
    const maxValue = Math.max(...aidAndYear.map(aidYear => aidYear.y));

    const options = {
        chart: {
            renderTo: "aid-graph-timeseries",
            type: "line",
            backgroundColor: "transparent",
        },
        title: false,
        series: [
            {
                name: "Aid from Norway to Africa (million USD)",
                data: aidAndYear,
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
            max: Math.ceil(maxValue * 1.1 / 100) * 100,
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
    };
    new Highcharts.Chart(options);
};

showAidTimeSeries();
