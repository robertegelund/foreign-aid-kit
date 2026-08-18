import { loadAllAidData } from "./oecd-api.js";

const sum = (series) => series.reduce((total, point) => total + point.y, 0);

let totalsPromise = null;

// Sums Norway's full ODA disbursement history to Africa and to all
// recipients worldwide ("ALLR" - Norway's true grand total, not just the
// narrower "developing countries" subset), in million USD. Memoized so
// every caller shares the same underlying fetch.
export const loadAidTotals = () => {
    if (!totalsPromise) {
        totalsPromise = loadAllAidData().then((allAidData) => {
            const africaSeries = allAidData["F"];
            const worldSeries = allAidData["ALLR"];
            return {
                africa: sum(africaSeries),
                world: sum(worldSeries),
                firstYear: africaSeries[0].name,
                lastYear: africaSeries[africaSeries.length - 1].name,
                series: africaSeries
            };
        });
    }
    return totalsPromise;
};
