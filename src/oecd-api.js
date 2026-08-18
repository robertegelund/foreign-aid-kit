// OECD SDMX API (DAC2A: Aid (ODA) disbursements to countries and regions).
// No API key required; CORS is supported (the API reflects back the request's Origin).
// DONOR=NOR (Norway), RECIPIENT=F (Africa region), MEASURE=206 (ODA disbursements),
// UNIT_MEASURE=USD, PRICE_BASE=V (current prices). Period is left open-ended so new
// years become available automatically as the OECD publishes them.
const OECD_AID_TIME_SERIES_URL =
    "https://sdmx.oecd.org/public/rest/data/OECD.DCD.FSD,DSD_DAC2@DF_DAC2A,1.6/NOR.F.206.USD.V?format=jsondata";

export const fetchAidTimeSeries = async () => {
    const response = await fetch(OECD_AID_TIME_SERIES_URL);
    if (!response.ok) {
        throw new Error(`OECD API request failed with status ${response.status}`);
    }
    const json = await response.json();

    const dataSet = json.data.dataSets[0];
    const seriesKey = Object.keys(dataSet.series)[0];
    const observations = dataSet.series[seriesKey].observations;
    const timePeriods = json.data.structures[0].dimensions.observation
        .find((dimension) => dimension.id === "TIME_PERIOD").values;

    return Object.entries(observations)
        .map(([index, value]) => ({
            name: timePeriods[Number(index)].id,
            y: value[0]
        }))
        .sort((a, b) => Number(a.name) - Number(b.name));
};
