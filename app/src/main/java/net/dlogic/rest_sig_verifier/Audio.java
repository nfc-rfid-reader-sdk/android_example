package net.dlogic.rest_sig_verifier;

import android.content.Context;
import android.media.AudioManager;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Build;
import android.os.VibrationEffect;
import android.os.Vibrator;

public class Audio {
    public static void Notify() {
        try {
            AudioManager audio = (AudioManager) GlobalApplication.getAppContext().getSystemService(Context.AUDIO_SERVICE);
            switch( audio.getRingerMode() ){
                case AudioManager.RINGER_MODE_NORMAL:
                    Uri notification = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
                    Ringtone r = RingtoneManager.getRingtone(GlobalApplication.getAppContext(), notification);
                    r.play();
                    break;
                case AudioManager.RINGER_MODE_SILENT:
                    break;
                case AudioManager.RINGER_MODE_VIBRATE:
                    Vibrator vibrator = (Vibrator) GlobalApplication.getAppContext().getSystemService(Context.VIBRATOR_SERVICE);
                    if (Build.VERSION.SDK_INT >= 26)
                        vibrator.vibrate(VibrationEffect.createOneShot(200, VibrationEffect.DEFAULT_AMPLITUDE));
                    else
                        vibrator.vibrate(200);
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
