import { MAPBOX_API_KEY } from "./config.js";
import {
    infoSectionTitle,
    totalAidReceived,
    totalAidAmount,
    aidPercentages,
    aidExplanation,
    aidGraphTimeseries,
    aidGraphUnspecified,
    aidStatus
} from "./dom.js";
import { aktiv, setAktiv, firstFly, setFirstFly } from "./state.js";
import { formatAidAmount, formatPercentage } from "./format.js";
import { MAPBOX_STYLE, STATIC_TOTAL_AID_AFRICA_MNOK } from "./constants.js";
import { loadAidTotals } from "./aid-totals.js";

mapboxgl.accessToken = MAPBOX_API_KEY;
export const kart = new mapboxgl.Map({
    container: "map",
    style: MAPBOX_STYLE
});

kart.on("load", () => {
    loadCountries();
});

const chart = new Highcharts.Chart({
    chart: {
        renderTo: "aid-graph-unspecified",
        type: "bar",
        backgroundColor: "transparent",
    },
    title: false,
    series: [{
        name: "Unallocated aid from Norway (MNOK)",
        color: "gold",
        borderColor: "transparent",
        data: []
    }],
    legend: {
        enabled: false
    },
    yAxis: {
        min: 0,
        max: 85,
        title: "",
        labels: { style: { color: "white" } }
    },
    xAxis: {
        categories: ["Unallocated"],
        labels: { style: { color: "white" } }
    }
});

export const showWorldAidOverview = async () => {
    let totals;
    try {
        totals = await loadAidTotals();
    } catch (error) {
        console.error("Failed to load aid totals from the OECD API:", error);
        return;
    }

    totalAidReceived.innerHTML = `<span class="total-aid">Aid Received</span> from ${totals.firstYear} to ${totals.lastYear}:`;
    totalAidAmount.innerHTML = `${Math.round(totals.africa).toLocaleString("en-US")} million USD`;
    aidPercentages.innerHTML = formatPercentage(totals.africa, totals.world);
    aidExplanation.innerHTML = "of the world's total aid from Norway";
};

showWorldAidOverview();

const loadCountries = async () => {
    const response = await fetch("./data/africa.geojson");
    const json = await response.json();
    json.features.forEach(addCountry);
};

const addCountry = (country) => {
    const name = country.properties.name;

    kart.addLayer({
        id: name,
        type: "fill",
        paint: {
            "fill-color": "transparent"
        },
        source: {
            type: "geojson",
            data: country.geometry
        }
    });

    kart.on("mouseover", name, () => highlightCountry(name, "rgba(0,0,0,0.3)"));
    kart.on("mouseleave", name, () => highlightCountry(name, "transparent"));
    kart.on("click", name, (e) => selectCountry(country, e));
};

const highlightCountry = (name, color) => {
    if (name !== aktiv) {
        kart.setPaintProperty(name, "fill-color", color);
    }
};

const selectCountry = (country, e) => {
    const name = country.properties.name;

    kart.setPaintProperty(aktiv, "fill-color", "transparent");
    setAktiv(name);
    kart.setPaintProperty(name, "fill-color", "rgba(230,0,0,0.3)");
    kart.setZoom(4);

    if (firstFly) {
        kart.flyTo({ center: [e.lngLat.lng, e.lngLat.lat] });
        setFirstFly(false);
    } else {
        kart.easeTo({ center: [e.lngLat.lng, e.lngLat.lat] });
    }

    updateCountryInfo(country);
};

const updateCountryInfo = (country) => {
    infoSectionTitle.innerHTML = country.properties.name;
    totalAidAmount.innerHTML = formatAidAmount(country.properties.aid);
    aidPercentages.innerHTML = formatPercentage(country.properties.aid, STATIC_TOTAL_AID_AFRICA_MNOK);
    aidExplanation.innerHTML = "of Africa's total aid from Norway";
    aidGraphTimeseries.style.display = "none";
    aidGraphUnspecified.style.display = "block";

    chart.series[0].update({
        data: [{
            name: "Unallocated",
            y: country.properties.unspecified
        }]
    });

    updateAidStatus(country);
};

const updateAidStatus = (country) => {
    if (country.properties.unspecified === 0) {
        aidStatus.style.display = "block";
        aidStatus.innerHTML = `All of ${country.properties.name}'s aid from Norway are allocated`;
    } else if (country.properties.unspecified === "NaN") {
        aidStatus.style.display = "block";
        aidStatus.innerHTML = `Whether any of ${country.properties.name}'s aid from Norway is unallocated is unsure`;
    } else {
        aidStatus.style.display = "none";
    }

    if (country.properties.aid === "NaN") {
        aidStatus.innerHTML = `${country.properties.name} has not received any aid from Norway`;
    }
};
