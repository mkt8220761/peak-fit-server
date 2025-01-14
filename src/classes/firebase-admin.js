import admin from "firebase-admin";
import { readFileSync } from "fs";
import { config } from "dotenv";
config();

let instance = null;

class FirebaseAdmin {
  constructor() {
    if (!instance) {
      try {
        // Read and parse the service account key
        const serviceAccount = JSON.parse(
          readFileSync(new URL("./service-account.json", import.meta.url))
        );

        // Initialize Firebase Admin SDK
        admin.initializeApp({
          credential: admin.credential.cert(serviceAccount),
          databaseURL: process.env.DATABASE_URL,
          storageBucket: process.env.STORAGE_BUCKET,
        });

        console.log("Firebase Admin Initialized", process.env.DATABASE_URL);
        instance = this; // Set the singleton instance
      } catch (error) {
        console.error("Error initializing Firebase Admin:", error.message);
        throw new Error("Failed to initialize Firebase Admin SDK");
      }
    }

    return instance;
  }

  getAuth() {
    return admin.auth();
  }

  getFirestore() {
    return admin.firestore();
  }

  getDatabase() {
    return admin.database();
  }

  getStorage() {
    return admin.storage().bucket();
  }
}

export default new FirebaseAdmin();
