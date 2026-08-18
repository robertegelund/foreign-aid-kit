import { loadAllAidData, loadDacToAfricaSeries } from "./oecd-api.js";

const sum = (series) => series.reduce((total, point) => total + point.y, 0);

let totalsPromise = null;

// Sums Norway's full ODA disbursement history to Africa, and how much of
// Africa's total received aid (from all DAC donor countries combined) that
// represents - i.e. Norway's share of the world's aid to Africa, not
// Africa's share of Norway's aid. Both sums cover the same year range
// (Norway's own first/last reported year) for an apples-to-apples
// percentage. Memoized so every caller shares the same underlying fetches.
export const loadAidTotals = () => {
    if (!totalsPromise) {
        totalsPromise = Promise.all([loadAllAidData(), loadDacToAfricaSeries()]).then(
            ([allAidData, dacToAfricaSeries]) => {
                const africaSeries = allAidData["F"];
                const firstYear = Number(africaSeries[0].name);
                const lastYear = Number(africaSeries[africaSeries.length - 1].name);
                const dacToAfricaInRange = dacToAfricaSeries.filter(
                    (point) => Number(point.name) >= firstYear && Number(point.name) <= lastYear
                );

                return {
                    africa: sum(africaSeries),
                    worldAidToAfrica: sum(dacToAfricaInRange),
                    firstYear: africaSeries[0].name,
                    lastYear: africaSeries[africaSeries.length - 1].name,
                    series: africaSeries
                };
            }
        );
    }
    return totalsPromise;
};
