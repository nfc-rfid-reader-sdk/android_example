package net.dlogic.util;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.text.TextUtils;
import android.widget.Toast;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringUtil {

    public static boolean isNumeric(String s){
        if(TextUtils.isEmpty(s)){
            return false;
        }
        Pattern p = Pattern.compile("[-+]?[0-9]*");
        Matcher m = p.matcher(s);
        return m.matches();
    }

    public static String subStrFromLastOf(String lastOf, String src) {
        String ret = src;

        if (null != src && src.length() > 0 )
        {
            int end_idx = src.lastIndexOf(lastOf);
            if ((end_idx > -1) && (end_idx < (src.length() - 1)))
            {
                ret = src.substring(end_idx + 1);
            }
        }

        return ret;
    }

    public static String getFileName(Context ctx, Uri uri) {
        String result = "";
        if (uri.getScheme().equals("content")) {
            Cursor cursor = null;
            try {
                cursor = ctx.getContentResolver().query(uri, null, null, null, null);
                if (cursor != null && cursor.moveToFirst()) {
                    result = cursor.getString(cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME));
                }
            } catch (java.lang.SecurityException e) {
                e.printStackTrace();
                Toast.makeText(ctx, "Permission Denial", Toast.LENGTH_LONG).show();
                return "";
            } finally {
                if (cursor != null)
                    cursor.close();
            }
        }
        if (result == "") {
            result = uri.getPath();
            int cut = result.lastIndexOf('/');
            if (cut != -1) {
                result = result.substring(cut + 1);
            }
        }
        return result;
    }
}
