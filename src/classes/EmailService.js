import nodemailer from "nodemailer";
import { google } from "googleapis";
import fs from "fs";
import { config } from "dotenv";
config();

class EmailService {
  constructor() {
    // Load OAuth2 credentials
    const credentials = JSON.parse(
      fs.readFileSync(new URL("./oauth2.json", import.meta.url), "utf-8")
    );

    const { client_id, client_secret, redirect_uris } = credentials.web;

    this.oAuth2Client = new google.auth.OAuth2(
      client_id,
      client_secret,
      redirect_uris[0]
    );

    // Set OAuth2 credentials
    this.oAuth2Client.setCredentials({
      refresh_token: process.env.OAUTH_REFRESH_TOKEN,
    });

    this.emailUser = process.env.EMAIL_USER;
    this.appPassword = process.env.EMAIL_APP_PASSWORD; // App Password from .env
  }

  async getAccessToken() {
    try {
      const accessToken = await this.oAuth2Client.getAccessToken();
      console.log("Access Token generated:", accessToken.token);
      return accessToken.token;
    } catch (error) {
      console.error("Error generating access token:", error.message);
      throw new Error("Failed to generate access token");
    }
  }

  async createTransporter(authType = "OAuth2") {
    try {
      if (authType === "OAuth2") {
        // OAuth2 Transporter
        const accessToken = await this.getAccessToken();

        return nodemailer.createTransport({
          service: "gmail",
          auth: {
            type: "OAuth2",
            user: this.emailUser,
            clientId: this.oAuth2Client._clientId,
            clientSecret: this.oAuth2Client._clientSecret,
            refreshToken: process.env.OAUTH_REFRESH_TOKEN,
            accessToken,
          },
        });
      } else if (authType === "AppPassword") {
        // App Password Transporter
        return nodemailer.createTransport({
          service: "gmail",
          auth: {
            user: this.emailUser,
            pass: this.appPassword,
          },
        });
      } else {
        throw new Error("Invalid authType. Choose 'OAuth2' or 'AppPassword'.");
      }
    } catch (error) {
      console.error("Error creating transporter:", error.message);
      throw new Error("Failed to create email transporter");
    }
  }

  async sendEmail(to, subject, html, authType = "AppPassword") {
    try {
      const transporter = await this.createTransporter(authType);

      const mailOptions = {
        from: this.emailUser,
        to,
        subject,
        html,
      };

      const result = await transporter.sendMail(mailOptions);
      console.log("Email sent successfully:", result);
      return result;
    } catch (error) {
      console.error("Error sending email:", error.message);
      throw new Error("Failed to send email");
    }
  }
}

export default new EmailService();
