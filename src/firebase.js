import { initializeApp } from "firebase/app"

const firebaseConfig = {
  apiKey: "AIzaSyDXv5ksRdJLOS3V8o6JoSYJkYyL5OhX_xY",
  authDomain: "foreign-aid-kit.firebaseapp.com",
  databaseURL: "https://foreign-aid-kit.firebaseio.com",
  projectId: "foreign-aid-kit",
  storageBucket: "foreign-aid-kit.appspot.com",
  messagingSenderId: "680222805848",
  appId: "1:680222805848:web:f373f9fe92c0f979de1f2d"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);