package net.dlogic.rest_sig_verifier;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import net.dlogic.util.StringUtil;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Created by d-logic on 12.02.2019.
 */

public class Main extends Activity {
    Context context;
    Button btnChooseFile;
    Button btnSignature;
    Button btnCertificate;
    Button btnVerify;
    TextView txtSiteUrl;
    EditText ebFile;
    EditText ebSignature;
    EditText ebCertificate;
    Spinner spnDigestAlgorithm;
    Spinner spnECDSASigFormat;

    private byte mECDSASigFormat = 0; // 0 => DER Encoded (default); 1 => r || s (legacy)
    private byte mDigestAlg = 2; // 0 => SHA1; 1 => SHA-224; 2 => SHA-256; 3 => SHA-384; 4 => SHA-512

    ProgressDialog mProgressDialog;
    ProgressDialog mSpinnerDialog;

    byte[] mDigest;
    byte[] mSignature;

    static Resources res;
    private static final int FILE_SELECT_CODE = 101;
    private static final int SIGNATURE_SELECT_CODE = 102;
    private static final int CERTIFICATE_SELECT_CODE = 103;
    final private static int REQUEST_CODE_ASK_PERMISSIONS = 301;
    private static final int DIALOG_HASH_PROGRESS = 0xAA55AA50;
    private static final int DIALOG_WAITING_FOR_SIGNATURE = 0xAA55AA51;
    private static final int DIGEST_CHUNK_SIZE = 1024 * 16; // 16 KB
    private static final int PROGRESS_SCALE = 100;
    public static final String LOG_TAG = "DL Signer Log";

    private Uri mFileUri = null;
    private Uri mSignUri = null;
    private Uri mCertUri = null;

    @Override
    protected void onPause() {
        super.onPause();
    }

    @Override
    protected void onResume() {
        super.onResume();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        context = this;

        // Get arrays from resources:
        res = getResources();

        // Get references to UI widgets:
        txtSiteUrl = findViewById(R.id.siteLogo);

        txtSiteUrl.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Uri siteUri = Uri.parse("http://" + getResources().getString(R.string.site_url));
                Intent browserIntent = new Intent(Intent.ACTION_VIEW, siteUri);

                startActivity(browserIntent);
            }
        });

        ebFile = findViewById(R.id.ebFile);
        ebFile.setInputType(0);
        ebSignature = findViewById(R.id.ebSignature);
        ebSignature.setInputType(0);
        ebCertificate = findViewById(R.id.ebCertificate);
        ebCertificate.setInputType(0);

        spnECDSASigFormat = findViewById(R.id.spnECDSASigFormat);
        ArrayAdapter<CharSequence> spnAuthenticationAdapter = ArrayAdapter.createFromResource(context,
                R.array.cipher_algorithms,
                R.layout.dl_spinner_textview);
        spnAuthenticationAdapter.setDropDownViewResource(R.layout.dl_spinner_textview);
        spnECDSASigFormat.setAdapter(spnAuthenticationAdapter);
        spnECDSASigFormat.setSelection(mECDSASigFormat);

        spnECDSASigFormat.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

            public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
                mECDSASigFormat = (byte) (pos & 0xFF);
            }

            public void onNothingSelected(AdapterView<?> parent) { }
        });

        spnDigestAlgorithm = findViewById(R.id.spnDigestAlgorithm);
        ArrayAdapter<CharSequence> spnLightAdapter = ArrayAdapter.createFromResource(context,
                R.array.digest_algorithms,
                R.layout.dl_spinner_textview);
        spnLightAdapter.setDropDownViewResource(R.layout.dl_spinner_textview);
        spnDigestAlgorithm.setAdapter(spnLightAdapter);

        spnDigestAlgorithm.setSelection(mDigestAlg);
        spnDigestAlgorithm.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

            public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
                mDigestAlg = (byte) ((pos & 0xFF) + 1);
            }

            public void onNothingSelected(AdapterView<?> parent) { }
        });

        btnChooseFile = findViewById(R.id.btnChooseFile);
        btnSignature = findViewById(R.id.btnSignature);
        btnCertificate = findViewById(R.id.btnCertificate);
        btnVerify = findViewById(R.id.btnVerify);

        btnChooseFile.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showFileChooser(FILE_SELECT_CODE);
            }
        });

        btnSignature.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showFileChooser(SIGNATURE_SELECT_CODE);
            }
        });

        btnCertificate.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showFileChooser(CERTIFICATE_SELECT_CODE);
            }
        });

        btnVerify.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {

                if (mFileUri != null && mSignUri != null && mCertUri != null) {
                    new HttpConnection().execute(new File(mFileUri.getPath()));
                }
            }
        });
    }

    private void showMessageOKCancel(String message, DialogInterface.OnClickListener okListener) {
        new AlertDialog.Builder(this)
                .setMessage(message)
                .setPositiveButton("OK", okListener)
                .setNegativeButton("Cancel", null)
                .create()
                .show();
    }

    // Progress bar settings:
    @Override
    protected Dialog onCreateDialog(int id) {
        switch (id) {
            case DIALOG_HASH_PROGRESS:
                mProgressDialog = new ProgressDialog(this);
                mProgressDialog.setMessage("Hashing file...");
                mProgressDialog.setIndeterminate(false);
                mProgressDialog.setMax(PROGRESS_SCALE);
                mProgressDialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
                mProgressDialog.setCancelable(false);
                mProgressDialog.setProgressNumberFormat(null);
                mProgressDialog.show();
                return mProgressDialog;
            case DIALOG_WAITING_FOR_SIGNATURE:
                mSpinnerDialog = new ProgressDialog(this);
                mSpinnerDialog.setMessage("Tap an DL Signer card to sign...");
                mSpinnerDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
                mSpinnerDialog.setCancelable(false);
                mSpinnerDialog.show();
                return mSpinnerDialog;
            default:
                return null;
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        String str;

        if (resultCode == Activity.RESULT_OK) {
            if (data != null) {
                Uri tempUri = data.getData();

                str = StringUtil.getFileName(this, tempUri);
                if (!str.equals("")) {

                    switch (requestCode) {
                        case FILE_SELECT_CODE:
                            mFileUri = tempUri;
                            ebFile.setText(str);
                            break;
                        case SIGNATURE_SELECT_CODE:
                            mSignUri = tempUri;
                            ebSignature.setText(str);
                            break;
                        case CERTIFICATE_SELECT_CODE:
                            mCertUri = tempUri;
                            ebCertificate.setText(str);
                            break;
                    }

                } else {
                    ebFile.setText("");
                    ebSignature.setText("");
                    ebCertificate.setText("");
                }
            }
        }

        super.onActivityResult(requestCode, resultCode, data);
    }

    private void showFileChooser(int requestCode) {

        if (Build.VERSION.SDK_INT >= 23) {
            int hasWriteContactsPermission = checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE);

            if (hasWriteContactsPermission != PackageManager.PERMISSION_GRANTED) {

                if (!shouldShowRequestPermissionRationale(Manifest.permission.WRITE_CONTACTS)) {
                    showMessageOKCancel("You need to allow access to external storage",
                            new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    requestPermissions(new String[] {Manifest.permission.READ_EXTERNAL_STORAGE},
                                            REQUEST_CODE_ASK_PERMISSIONS);
                                }
                            });
                    return;
                }

                requestPermissions(new String[] {Manifest.permission.READ_EXTERNAL_STORAGE}, REQUEST_CODE_ASK_PERMISSIONS);
                return;
            }
        }

        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);

        try {
            startActivityForResult(Intent.createChooser(intent, "Select a File to Sign"), requestCode);

        } catch (android.content.ActivityNotFoundException ex) {
            // Potentially direct the user to the Market with a Dialog
            Toast.makeText(this, "Please install a File Manager.", Toast.LENGTH_SHORT).show();
        }
    }

    class HttpConnection extends AsyncTask<File, Void, Boolean> {
        String mToastMsg = "";

        @Override
        protected void onPreExecute() {
            showDialog(DIALOG_WAITING_FOR_SIGNATURE);
        }

        @Override
        protected Boolean doInBackground(File... files) {


            try {

                JSONObject json_params = new JSONObject();
                json_params.put("operation", "verify");
                json_params.put("ecdsa_sig_format", mECDSASigFormat);
                json_params.put("digest_algo", mDigestAlg);

                // Dlogic:
                String requestURL = "https://certificates.d-logic.com/rest_sig_verifier/verify.php";

                // Debug:
                //String requestURL = "http://192.168.1.67/rest_sig_verifier/verify.php";

                String charset = "UTF-8";

                MultipartUtility multipart = new MultipartUtility(requestURL, charset);

                multipart.addFilePart("file", new File(mFileUri.getPath()));
                multipart.addFilePart("signature", new File(mSignUri.getPath()));
                multipart.addFilePart("certificate", new File(mCertUri.getPath()));

                multipart.addFormField("query", json_params.toString());

                List<String> response = multipart.finish();

                JSONObject json = new JSONObject(response.get(0));
                String status  = json.getString("status");
                String msg  = json.getString("msg");

                mToastMsg = status;
                if (msg != "")
                    mToastMsg += "\r\n" + msg;

            } catch (IOException e) {
                e.printStackTrace();
                mToastMsg = e.getMessage();
                return false;
            } catch (JSONException e) {
                e.printStackTrace();
                mToastMsg = e.getMessage();
                return false;
            }

            return true;
        }

        @Override
        protected void onPostExecute(Boolean success) {
            dismissDialog(DIALOG_WAITING_FOR_SIGNATURE);
            Toast.makeText(Main.this, mToastMsg, Toast.LENGTH_LONG).show();
        }
    }

    public class MultipartUtility {
        private final String boundary;
        private static final String LINE_FEED = "\r\n";
        private HttpURLConnection httpConn;
        private String charset;
        private OutputStream outputStream;
        private PrintWriter writer;

        /**
         * This constructor initializes a new HTTP POST request with content type
         * is set to multipart/form-data
         *
         * @param requestURL
         * @param charset
         * @throws IOException
         */
        public MultipartUtility(String requestURL, String charset)
                throws IOException {
            this.charset = charset;

            // creates a unique boundary based on time stamp
            byte[] array = new byte[20];
            Random randomGenerator = new Random();
            for (int i = 0; i < array.length; i++)
                array[i] = (byte) (randomGenerator.nextFloat() * 10 + 0x30);
            boundary = new String(array, Charset.forName("US-ASCII"));

            URL url = new URL(requestURL);
            httpConn = (HttpURLConnection) url.openConnection();
            httpConn.setUseCaches(false);
            httpConn.setDoOutput(true); // indicates POST method
            httpConn.setDoInput(true);
            httpConn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
            //httpConn.setRequestProperty("User-Agent", "CodeJava Agent");
            //httpConn.setRequestProperty("Test", "Bonjour");
            outputStream = httpConn.getOutputStream();
            writer = new PrintWriter(new OutputStreamWriter(outputStream, charset), true);
        }

        /**
         * Adds a form field to the request
         *
         * @param name  field name
         * @param value field value
         */
        public void addFormField(String name, String value) {
            writer.append("--" + boundary).append(LINE_FEED);
            writer.append("Content-Disposition: form-data; name=\"" + name + "\"").append(LINE_FEED);
            writer.append("Content-Type: text/plain; charset=" + charset).append(LINE_FEED);
            writer.append(LINE_FEED);
            writer.append(value).append(LINE_FEED);
            writer.flush();
        }

        /**
         * Adds a upload file section to the request
         *
         * @param fieldName  name attribute in <input type="file" name="..." />
         * @param uploadFile a File to be uploaded
         * @throws IOException
         */
        public void addFilePart(String fieldName, File uploadFile) throws IOException {
            String fileName = uploadFile.getName();
            writer.append("--" + boundary).append(LINE_FEED);
            writer.append("Content-Disposition: form-data; name=\"" + fieldName
                            + "\"; filename=\"" + fileName + "\"").append(LINE_FEED);
            writer.append("Content-Type: "
                            + URLConnection.guessContentTypeFromName(fileName)).append(LINE_FEED);
            writer.append("Content-Transfer-Encoding: binary").append(LINE_FEED);
            writer.append(LINE_FEED);
            writer.flush();

            FileInputStream inputStream = new FileInputStream(uploadFile);
            byte[] buffer = new byte[4096];
            int bytesRead = -1;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            outputStream.flush();
            inputStream.close();

            writer.append(LINE_FEED);
            writer.flush();
        }

        /**
         * Adds a header field to the request.
         *
         * @param name  - name of the header field
         * @param value - value of the header field
         */
        public void addHeaderField(String name, String value) {
            writer.append(name + ": " + value).append(LINE_FEED);
            writer.flush();
        }

        /**
         * Completes the request and receives response from the server.
         *
         * @return a list of Strings as response in case the server returned
         * status OK, otherwise an exception is thrown.
         * @throws IOException
         */
        public List<String> finish() throws IOException {
            List<String> response = new ArrayList<String>();

            writer.append(LINE_FEED).flush();
            writer.append("--" + boundary + "--").append(LINE_FEED);
            writer.close();

            // checks server's status code first
            int status = httpConn.getResponseCode();
            if (status == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(httpConn.getInputStream()));
                String line = null;
                while ((line = reader.readLine()) != null) {
                    response.add(line);
                }
                reader.close();
                httpConn.disconnect();
            } else {
                throw new IOException("Server returned non-OK status: " + status);
            }

            return response;
        }
    }
}
