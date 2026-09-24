package wtf.oxff.blox

import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import wtf.oxff.blox.ui.BloxRoot
import wtf.oxff.blox.ui.BloxTheme

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, recording or Recents thumbnails anywhere: every screen shows either
        // the recovery phrase, a QR secret or a request (§10.6).
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) window.setHideOverlayWindows(true)
        window.decorView.filterTouchesWhenObscured = true

        val app = application as BloxApp
        lifecycle.addObserver(
            LifecycleEventObserver { _, event ->
                when (event) {
                    Lifecycle.Event.ON_STOP -> app.session.onBackground()
                    Lifecycle.Event.ON_START -> app.session.onForeground()
                    else -> {}
                }
            },
        )
        setContent { BloxTheme { BloxRoot(this, app) } }
    }

    fun keepScreenOn(on: Boolean) {
        if (on) window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }
}
