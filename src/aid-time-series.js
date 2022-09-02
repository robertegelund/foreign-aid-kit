const showAidTimeSeries = async () => {
    const response = await fetch("./data/aid-data.json");
    const json = await response.json();
    const aidAndYear = await json.aid;

    const years = aidAndYear.map( 
        aidYear => aidYear.name); 

const options = {
    chart: {
        renderTo: "aid-graph-timeseries",
        type: "line",
        backgroundColor: "transparent",
    },
    title: false,
    series: [
        {
            name: "Aid from Norway to Africa (MNOK)",
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
        max: 6500,
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
}
    new Highcharts.Chart(options);
}

showAidTimeSeries();