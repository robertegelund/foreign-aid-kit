import { loadAllAidData } from "./oecd-api.js";
import { COUNTRY_OECD_CODES } from "./country-codes.js";

const sum = (series) => series.reduce((total, point) => total + point.y, 0);

let countryDataPromise = null;

// Norway's full ODA disbursement history to each African country, in
// million USD, keyed by the country names used in data/africa.geojson.
// Each entry is { series, total } (both null for countries with no OECD
// recipient code - Western Sahara, Somaliland - or no recorded
// disbursements). Memoized so every caller shares the same underlying fetch.
export const loadCountryAidData = () => {
    if (!countryDataPromise) {
        countryDataPromise = loadAllAidData().then((allAidData) => {
            const byCountry = {};
            Object.entries(COUNTRY_OECD_CODES).forEach(([countryName, code]) => {
                const series = allAidData[code] ?? null;
                byCountry[countryName] = {
                    series,
                    total: series ? sum(series) : null
                };
            });
            return byCountry;
        });
    }
    return countryDataPromise;
};
