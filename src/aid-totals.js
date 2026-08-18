import { fetchAidSeries } from "./oecd-api.js";

const sum = (series) => series.reduce((total, point) => total + point.y, 0);

let loadPromise = null;

// Fetches and sums Norway's full ODA disbursement history to Africa and to
// all developing countries ("the world"), in million USD. Memoized so every
// caller shares the same two API calls instead of re-fetching.
export const loadAidTotals = () => {
    if (!loadPromise) {
        loadPromise = Promise.all([
            fetchAidSeries("F"),
            fetchAidSeries("DPGC")
        ]).then(([africaSeries, worldSeries]) => ({
            africa: sum(africaSeries),
            world: sum(worldSeries),
            firstYear: africaSeries[0].name,
            lastYear: africaSeries[africaSeries.length - 1].name
        }));
    }
    return loadPromise;
};
