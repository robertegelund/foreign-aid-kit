import { loadAllAidData } from "./oecd-api.js";
import { COUNTRY_OECD_CODES } from "./country-codes.js";

const sum = (series) => series.reduce((total, point) => total + point.y, 0);

let countryTotalsPromise = null;

// Sums Norway's full ODA disbursement history to each African country, in
// million USD, keyed by the country names used in data/africa.geojson.
// Countries with no OECD recipient code (Western Sahara, Somaliland) or no
// recorded disbursements map to null. Memoized so every caller shares the
// same underlying fetch.
export const loadCountryAidTotals = () => {
    if (!countryTotalsPromise) {
        countryTotalsPromise = loadAllAidData().then((allAidData) => {
            const totals = {};
            Object.entries(COUNTRY_OECD_CODES).forEach(([countryName, code]) => {
                const series = allAidData[code];
                totals[countryName] = series ? sum(series) : null;
            });
            return totals;
        });
    }
    return countryTotalsPromise;
};
