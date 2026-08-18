import { MAPBOX_API_KEY } from "./config.js";
import {
    infoSectionTitle,
    totalAidReceived,
    totalAidAmount,
    aidPercentages,
    aidExplanation,
    aidStatus
} from "./dom.js";
import { aktiv, setAktiv, firstFly, setFirstFly } from "./state.js";
import { formatPercentage } from "./format.js";
import { MAPBOX_STYLE } from "./constants.js";
import { loadAidTotals } from "./aid-totals.js";
import { loadCountryAidData } from "./country-aid.js";
import { showAidTimeSeries } from "./aid-time-series.js";

mapboxgl.accessToken = MAPBOX_API_KEY;
export const kart = new mapboxgl.Map({
    container: "map",
    style: MAPBOX_STYLE
});

kart.on("load", () => {
    loadCountries();
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
    aidPercentages.innerHTML = formatPercentage(totals.africa, totals.worldAidToAfrica);
    aidExplanation.innerHTML = "of the world's total aid to Africa is from Norway";
    aidStatus.style.display = "none";
    showAidTimeSeries(totals.series, "Aid from Norway to Africa (million USD)");
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

const updateCountryInfo = async (country) => {
    const name = country.properties.name;
    infoSectionTitle.innerHTML = name;

    let totals, countryData;
    try {
        [totals, countryData] = await Promise.all([loadAidTotals(), loadCountryAidData()]);
    } catch (error) {
        console.error("Failed to load aid data from the OECD API:", error);
        return;
    }

    const countryInfo = countryData[name];
    if (!countryInfo || countryInfo.total === null) {
        totalAidAmount.innerHTML = "No data available";
        aidPercentages.innerHTML = "";
        aidExplanation.innerHTML = "";
        aidStatus.style.display = "block";
        aidStatus.innerHTML = `No OECD-reported aid data is available for ${name}`;
    } else {
        totalAidAmount.innerHTML = `${Math.round(countryInfo.total).toLocaleString("en-US")} million USD`;
        aidPercentages.innerHTML = formatPercentage(countryInfo.total, totals.africa);
        aidExplanation.innerHTML = "of Africa's total aid from Norway";
        aidStatus.style.display = "none";
        showAidTimeSeries(countryInfo.series, `Aid from Norway to ${name} (million USD)`);
    }
};
