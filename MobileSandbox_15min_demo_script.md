# MobileSandbox 15-Minute Demo Script

## Slide 1: Project Overview and Problem Statement
**Time: 2 minutes**

MobileSandbox is an Android security and privacy analysis system. The problem it solves is that users often install apps without understanding what permissions are requested and what privacy risk those permissions create.

The project has two main parts:
- Android mobile app: scans installed apps and selected APK files before installation.
- FastAPI analysis server: calculates risk score, classifies risk level, stores scan history, and learns from feedback.

Key output shown to the user:
- Risk score from 0 to 100.
- Risk level: SAFE, HANDLE WITH CARE, SUSPICIOUS, or DANGEROUS.
- PII permissions and sensitive permissions detected.
- Scan history and feedback options.

## Slide 2: System Architecture
**Time: 3 minutes**

The workflow starts in the Android app. The app reads package names and permissions using Android PackageManager. For pre-install APK analysis, the APK is copied into app-private cache first, so the file can be inspected without installing.

The app sends package name and permission list to the backend `/analyze` API. The FastAPI server calls the ML engine, calculates score and risk level, and saves the result in SQLite.

Main backend endpoints:
- `POST /analyze`: permission analysis and risk scoring.
- `POST /feedback`: user marks app as safe or malware.
- `GET /scan/history`: scan history for the app.
- `GET /stats`: aggregate scan and feedback statistics.
- `POST /retrain`: manual background model retraining.

## Slide 3: Risk Scoring and ML Workflow
**Time: 4 minutes**

The scoring engine uses a hybrid model instead of only one rule.

Signal A is static permission risk. Examples: SMS, contacts, call logs, background location, install packages, camera, and audio have higher risk weights.

Signal B is a GradientBoostingClassifier trained on the dataset. It predicts class probabilities and contributes an ML-based risk signal.

Signal C is a safe-biased Bayesian prior. Unknown apps start closer to safe unless the permission evidence increases risk.

The final score is a weighted blend:
- Static permissions: 58 percent when ML is available.
- ML signal: 24 percent.
- Bayesian prior: 18 percent.

Extra calibration:
- Dangerous permission combinations increase risk.
- Apps with few permissions get a dampener.
- Many low-risk permissions do not unfairly increase the score.
- Known safe package prefixes can cap scores.
- Confidence shows whether internal signals agree.

## Slide 4: App Features and User Workflow
**Time: 3 minutes**

Installed app scan:
1. User taps scan.
2. App reads installed non-system apps.
3. Permissions are sent to the server.
4. Result cards show risk level, score meter, PII permissions, and sensitive permissions.
5. User can mark result as Safe or Malware.

Pre-install APK scan:
1. User picks one APK or multiple split APK files.
2. Files are staged inside the app sandbox.
3. Package name and permissions are extracted without installation.
4. User can reject and delete the staged file, or continue to Android installer.

History workflow:
- Scan history is saved in SQLite.
- The History tab fetches recent scans and shows total scan count.
- Duplicate scans within a short window are skipped to avoid noisy history.

## Slide 5: Demo Plan, Validation, and Future Scope
**Time: 3 minutes**

Live demo order:
1. Start backend server from `analysis_server`.
2. Open Android app.
3. Run installed-app scan and explain result card.
4. Open History tab and show saved scans.
5. Pick an APK for pre-install scan.
6. Show Safe/Malware feedback buttons.
7. Optionally open `/stats` or `/ratings/progression` in browser.

Validation points:
- Backend initializes SQLite tables.
- Model loads from `analysis_server/model`.
- API returns score, risk level, PII list, sensitive list, and confidence.
- Android UI handles scan loading, results, history, and pre-install decision.

Future improvements:
- Add richer APK static analysis beyond permissions.
- Add explainability per score: top reasons for risk.
- Add cloud deployment for backend.
- Improve model with larger real-world malware dataset.
- Add authentication and per-user dashboards.

