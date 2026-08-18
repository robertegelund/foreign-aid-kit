export const formatAidAmount = (aid) => {
    const number = Number(aid);
    if (Number.isNaN(number)) return `${aid} MNOK`;
    return `${number.toLocaleString("en-US")} MNOK`;
};

export const formatPercentage = (part, total) => `${(part * 100 / total).toFixed(2)} %`;
