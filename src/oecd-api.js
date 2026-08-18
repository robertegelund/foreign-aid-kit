// OECD SDMX API (DAC2A: Aid (ODA) disbursements to countries and regions).
// No API key required; CORS is supported (the API reflects back the request's
// Origin). MEASURE=206 (ODA disbursements), UNIT_MEASURE=USD, PRICE_BASE=V
// (current prices).
//
// CSV format is used deliberately instead of the JSON API: when RECIPIENT
// has multiple values, the OECD's JSON response contains duplicate object
// keys per series (one per recipient+year combination sharing the same
// dimension-index key), which standard JSON parsing silently collapses to
// just the last observation - confirmed by direct testing. CSV has no such
// ambiguity since every observation is its own row.
import { COUNTRY_OECD_CODES } from "./country-codes.js";

const dacUrl = (donor, recipients) =>
    `https://sdmx.oecd.org/public/rest/data/OECD.DCD.FSD,DSD_DAC2@DF_DAC2A,1.6/${donor}.${recipients}.206.USD.V?format=csvfile`;

// DONOR=NOR (Norway). RECIPIENT is a joined list of every recipient this app
// needs Norway's own figures for (individual African countries plus "F" =
// Africa region), fetched in one request.
const RECIPIENT_CODES = ["F", ...new Set(Object.values(COUNTRY_OECD_CODES))];
const OECD_URL = dacUrl("NOR", RECIPIENT_CODES.join("+"));

let loadPromise = null;

// Fetches Norway's full ODA disbursement history for every recipient this
// app needs, in a single request. Memoized so every caller (time-series
// chart, world/Africa totals, per-country totals) shares the same fetch.
export const loadAllAidData = () => {
    if (!loadPromise) {
        loadPromise = fetch(OECD_URL).then(async (response) => {
            if (!response.ok) {
                throw new Error(`OECD API request failed with status ${response.status}`);
            }
            return parseAidCsv(await response.text());
        });
    }
    return loadPromise;
};

// DONOR=DAC ("DAC countries" - the standard aggregate for all major donor
// countries combined, i.e. Norway's peers). Used to show how much of
// Africa's total received aid comes from Norway specifically, rather than
// how much of Norway's own aid goes to Africa.
const DAC_TO_AFRICA_URL = dacUrl("DAC", "F");

let dacToAfricaPromise = null;

export const loadDacToAfricaSeries = () => {
    if (!dacToAfricaPromise) {
        dacToAfricaPromise = fetch(DAC_TO_AFRICA_URL).then(async (response) => {
            if (!response.ok) {
                throw new Error(`OECD API request failed with status ${response.status}`);
            }
            return parseAidCsv(await response.text())["F"];
        });
    }
    return dacToAfricaPromise;
};

const parseAidCsv = (csvText) => {
    const lines = csvText.trim().split("\n");
    const header = lines[0].split(",");
    const recipientIndex = header.indexOf("RECIPIENT");
    const timePeriodIndex = header.indexOf("TIME_PERIOD");
    const obsValueIndex = header.indexOf("OBS_VALUE");

    const byRecipient = {};
    for (let i = 1; i < lines.length; i++) {
        const columns = lines[i].split(",");
        const recipientCode = columns[recipientIndex];
        (byRecipient[recipientCode] ??= []).push({
            name: columns[timePeriodIndex],
            y: Number(columns[obsValueIndex])
        });
    }

    Object.values(byRecipient).forEach((series) =>
        series.sort((a, b) => Number(a.name) - Number(b.name))
    );
    return byRecipient;
};
