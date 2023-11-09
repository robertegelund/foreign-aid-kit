import { initializeApp } from "firebase/app"
import firebase from "../api_info.js";

const firebaseConfig = {
  apiKey: firebase["API_KEY"],
  authDomain: "foreign-aid-kit.firebaseapp.com",
  databaseURL: "https://foreign-aid-kit.firebaseio.com",
  projectId: "foreign-aid-kit",
  storageBucket: "foreign-aid-kit.appspot.com",
  messagingSenderId: firebase["MESSAGING_SENDER_ID"],
  appId: firebase["APP_ID"]
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);