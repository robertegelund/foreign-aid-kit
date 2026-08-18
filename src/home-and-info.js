import { kart, showWorldAidOverview } from "./africa-map.js";
import {
    iconHome,
    iconInfo,
    whatAndHowTo,
    chooseContinent,
    chooseContinentAfrica,
    infoSectionContainer,
    infoSectionTitle,
    aidStatus
} from "./dom.js";
import { aktiv, infoOpen, setInfoOpen } from "./state.js";

iconHome.onclick = () => {
    kart.flyTo({
        center: [17.525, 23.074],
        zoom: 2
    });
    kart.setPaintProperty(aktiv, "fill-color", "transparent");

    infoSectionTitle.innerHTML = "Africa";
    showWorldAidOverview();

    infoSectionContainer.style.display = "none";
    whatAndHowTo.style.display = "flex";
    chooseContinent.style.display = "block";
    aidStatus.style.display = "none";

    iconInfo.style.color = "gold";
    iconInfo.style.animation = "pulsate 1.5s infinite";
    setInfoOpen(true);
};

iconInfo.onclick = () => {
    if (infoOpen) {
        whatAndHowTo.style.display = "none";
        infoSectionContainer.style.display = "flex";
        iconInfo.style.color = "white";
        iconInfo.style.animationPlayState = "paused";
    } else {
        whatAndHowTo.style.display = "flex";
        chooseContinent.style.display = "block";
        infoSectionContainer.style.display = "none";
        iconInfo.style.color = "gold";
        iconInfo.style.animation = "pulsate 1.5s infinite";
    }
    setInfoOpen(!infoOpen);
};

chooseContinentAfrica.onclick = () => {
    kart.flyTo({
        center: [41.657048, -6.813934],
        zoom: 2.50,
        pitch: 40,
        minPitch: 40,
        maxPitch: 40
    });
    infoSectionContainer.style.display = "flex";
    whatAndHowTo.style.display = "none";
    iconInfo.style.color = "white";
    iconInfo.style.animationPlayState = "paused";
};
