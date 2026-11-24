# PE Forensics | Explainable malware classification for Windows executables

## Project overview for the evaluator

This project examines a Windows executable without running it and answers two questions. First, how closely do its header fields resemble the malware cases in a labeled training set? Second, which structural observations might warrant investigation for packing? The first answer comes from a trained classifier. The second comes from inspecting the file's sections, permissions and byte entropy.

The experiment compared three classifiers on 823 held-out feature vectors. Random forest achieved the highest F1 score (0.934). The interactive application deploys logistic regression (F1 0.713) so an evaluator can trace each prediction back to the measured inputs. Its 71 false alarms and 120 missed malware cases illustrate the limits of using header fields alone.

| What to evaluate | Where to find it |
|---|---|
| Can another reviewer identify the same input? | Analyze a local EXE or DLL and compare the reported SHA-256 with PowerShell's `Get-FileHash` output. |
| Can the prediction be explained? | Select a held-out record and inspect the baseline, individual contributions and final log-odds. |
| How well did each model perform? | Expand **Model evaluation and global explanations** to inspect precision, recall and confusion counts. |
| Can the experiment be repeated? | Follow **Reproduce the experiment** below to verify the source CSV and regenerate the model and scores. |

## Run the application

Open **Open Demo.html** in Chrome or Edge. Keep the adjacent JavaScript files in the same folder. The demo runs offline without Python, a server, or installation.

## Three-minute demonstration

1. **Show the evidence first.** Choose a PE file and enter `C:\Windows\System32\notepad.exe` in the Windows file dialog. Point out the SHA-256 fingerprint, file size and PE format. The browser reads the file as bytes. Its hash identifies the input and never enters the model.
2. **Explain the prediction.** Read the malicious-class score. The deployed logistic regression uses 15 header fields. A score of 0.50 or above receives the malicious-like label. Open “All header values and model contributions.” Positive contributions raise the log-odds, negative contributions lower them. The sum plus the baseline reconstructs the prediction.
3. **Inspect the packing evidence.** Expand “Sections and imports.” Entropy measures diversity of byte values. Compressed resources can also produce high entropy. Section names and writable/executable permissions are descriptive clues. No verified packing labels were available for a separate packing experiment.
4. **Compare two labeled cases.** Click “Benign record,” then “Malware record.” Each button runs inference on an actual held-out feature vector. These examples were chosen from correctly classified cases at the median score within each correctly classified class. They illustrate the workflow. The evaluation below includes errors.
5. **Show measured results.** Open “Model evaluation and global explanations.” All three models saw the same training rows. The forest had the highest measured F1 on this split. The live demo uses logistic regression because its prediction can be reconstructed exactly from the displayed contributions.
6. **Save the evidence.** Select a real file again and click “Save JSON report.” Open the download to show the input hash, UTC analysis time, model version, all feature values, contributions, section statistics, import DLLs, parser warnings, and packing observations. The reference records have no original bytes or file digest.

## Results

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | False-positive rate |
|---|---:|---:|---:|---:|---:|---:|
| Logistic regression (live) | 76.8% | 76.9% | 66.4% | 0.713 | 0.867 | 15.2% |
| Random forest | 94.3% | 94.3% | 92.4% | 0.934 | 0.988 | 4.3% |
| Gradient boosting | 89.7% | 87.8% | 88.5% | 0.881 | 0.969 | 9.4% |

Of the 357 malware records in the test set, logistic regression identified 237 and missed 120. It flagged 71 of the 466 benign records. File-level decisions need independent review.

## Methods and limitations

The source is Ajit Kumar and collaborators’ [ClaMP repository](https://github.com/urwithajit9/ClaMP), specifically [ClaMP_Raw-5184.csv](https://raw.githubusercontent.com/urwithajit9/ClaMP/master/dataset/ClaMP_Raw-5184.csv). The source maps 0 to benign and 1 to malware. This implementation uses ClaMP in place of the paper’s proposed EMBER benchmark. The source CSV contains pre-extracted measurements. It allows an experiment without distributing executable samples.

We collapsed the 5,184 rows to 4,111 distinct vectors over the 15 selected inputs. None of these vectors carried conflicting labels. A stratified split (seed 42) placed 3,288 vectors in training and 823 in testing. We fixed the hyperparameters before testing. The training split alone supplies the mean and scale after the log(1+x) transform. The source does not provide family or date groupings in this table. Related builds may cross the split, and performance on contemporary Windows files remains unknown.

The analyzer reads COFF and PE32/PE32+ optional headers, section records and the ordinary import directory. It records imported DLL names. Delay-loaded imports, individual API calls, runtime unpacking and behavior analysis are outside this implementation. The model uses header fields shared with ClaMP. Entropy, import names and section observations supplement the forensic report. High entropy means at least 7.2 bits/byte over a section of at least 512 bytes in this demo. Other indicators include a writable/executable section or a UPX-style section name. These are heuristics and have no measured packing accuracy.

For the standardized log-transformed inputs, the linear model has baseline log-odds equal to its intercept. Under the interventional SHAP definition each contribution is the coefficient times its centered, scaled feature. This is exact on the log-odds scale. Correlated header fields can share information. The explanation describes the model, and its score has no independent calibration. Global influence is mean absolute contribution on the test split.

## Reproduce the experiment

Use Python 3.12. From this project folder in PowerShell run the following. Internet access is needed for the initial dependencies and dataset download.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install numpy==2.3.5 scipy==1.16.3 scikit-learn==1.6.1 joblib==1.5.2 threadpoolctl==3.6.0
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/urwithajit9/ClaMP/master/dataset/ClaMP_Raw-5184.csv" -OutFile raw.csv
.\.venv\Scripts\python.exe train.py raw.csv
```

Training verifies the CSV's SHA-256, fits all three models, prints their confusion counts and metrics, and rewrites model.js with the logistic coefficients, comparison results and two example inputs. Reload Open Demo.html to use the new export. analyzer.js contains the PE reader and inference code. interface.js generates the visible report and JSON export.

